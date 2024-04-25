---
title: KernelCallbackTable
tags: Windows
---
## 0x00 简介

Windows 中有窗口的程序就有可能 ring0 直接调用 ring3的程序，KernelCallbackTable 就用于从内核回调用户空间的函数，因此可以用于 ring0 执行 ring3 代码

## 0x01 调用

KeUserModeCallback 函数原型：

```C
NTSTATUS
KeUserModeCallback (
     IN ULONG ApiNumber,
     IN PVOID InputBuffer,
     IN ULONG InputLength,
     OUT PVOID *OutputBuffer,
     IN PULONG OutputLength
     );
```


KeUserModeCallback 调用过程：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095936.png)

重点：

- 回调函数的第一个参数是 KeUserModeCallback 的第二个参数InputBuffer，第二个参数是   KeUserModeCallback 的第三个参数InputLength

- KeUserModeCallback 必须在用户进程的线程上下文中被调用才能成功，因为需要用户堆栈空间

## 0x02 寻找 KernelCallbackTable

KernelCallbackTable 的结果在 PEB 中能找到，因此需要先找到一个进程的 PEB:

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095940.png)

查看 peb 结构`dt _peb 000000c191a7c000` 找到 KernelCallbackTable：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095942.png)

dps 会显示给定范围的内存内容。当该内存是符号表中的一系列地址时，相应的符号也会显示出来

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095948.png)

## 0x03 寻找指定回调函数偏移

根据 0x02 使用 dps 看到的 KernelCallbackTable 内容，找到 USER32!_xxxClientAllocWindowClassExtraBytes 函数地址：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095952.png)

计算偏移：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329095955.png)

因此如果需要在代码里调用或 hook USER32!_xxxClientAllocWindowClassExtraBytes，则代码应为：

```C
typedef NTSTATUS(WINAPI* FxxxClientAllocWindowClassExtraBytes)(unsigned int* pSize);
FxxxClientAllocWindowClassExtraBytes g_fxxxClientAllocWindowClassExtraBytes = NULL;

ULONG_PTR pKernelCallbackTable = (ULONG_PTR) *(ULONG_PTR*)(__readgsqword(0x60) + 0x58); // gs:[0x60] 指向进程 PEB，PEB 结构体偏移 0x58 为 KernelCallbackTable

g_fxxxClientAllocWindowClassExtraBytes = (FxxxClientAllocWindowClassExtraBytes)*(ULONG_PTR*)((PBYTE)pKernelCallbackTable + 0x3D8);  //KernelCallbackTable 偏移0x3D8 为 user32!_xxxClientAllocWindowClassExtraBytes

*(ULONG_PTR*)((PBYTE)pKernelCallbackTable + 0x3D8) = (ULONG_PTR)MyxxxClientAllocWindowClassExtraBytes;  // hook user32!_xxxClientAllocWindowClassExtraBytes 为自定义函数 MyxxxClientAllocWindowClassExtraBytes

```



