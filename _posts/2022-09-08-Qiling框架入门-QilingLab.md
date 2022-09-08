---
title: Qiling框架入门-QilingLab
tags: IOT
---

## 0x00 简介

Qiling框架是基于unicorn的多架构平台模拟执行框架，本质上是在沙箱环境内模拟执行二进制文件，在模拟执行的基础上提供统一的分析API，这个API包括插桩分析、快照、系统调用和API劫持等。

QilingLab是受FridaLab的启发，由11个小挑战组成的二进制程序，用来帮助新手快速熟悉和掌握 Qiling 框架的基本用法。

QilingLab 下载地址：https://www.shielder.com/attachments/qilinglab-aarch64

QilingLab rootfs 下载地址：https://github.com/qilingframework/rootfs/tree/master/arm64_linux

Qiling文档：https://docs.qiling.io/en/latest/

实验环境以及exp都打包在github里了：https://github.com/Ryze-T/qilinglab-slov

挑战如下：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220902172919-u7rgsgo.png)​

## 0x01 挑战

exp模板如下：

```python
from qiling import *
from qiling.const import *


def challengeX(ql: Qiling):
    pass


if __name__ == "__main__":
    target = ['./qilinglab-aarch64']
    rootfs = "./arm64_linux"
    ql = Qiling(target, rootfs, verbose=QL_VERBOSE.DEFAULT)
    challengeX(ql)
    ql.run()
```

### 1. Challenge1

Challenge1: 在0x1337地址处写入1337

操作内存：https://docs.qiling.io/en/latest/memory/

根据文档，写入内存之前需要先调用 mem.map 映射内存区域，再调用 mem.write 写入，因此exp如下：

```python
def challenge1(ql: Qiling):
    addr = 0x1337
    ql.mem.map(addr // 4096 * 4096, 0x1000)
    ql.mem.write(addr, ql.pack16(1337))
```

### 2. Challenge2

Challenge2: 使系统调用uname返回正确的值

先判断正确的值是什么：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220905160058-v2l5cj2.png)​

需要 utsname.sysname = QilingOS，utsname.version = ChallengeStart。

utsname结构体如下：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220905163348-i96pp76.png)​

通过 os.set_syscall 加上 QL_INTERCEPT.EXIT 参数，在调用结束后劫持 uname 的返回值，替换成验证的字符串，参考文档：https://docs.qiling.io/en/latest/hijack/。

```c
def fake_uname(ql: Qiling, pName, *args):
    ql.mem.write(pName, b'QilingOS\x00')
    ql.mem.write(pName + 65 * 3, b'ChallengeStart\x00')


def challenge2(ql: Qiling):
    ql.os.set_syscall('uname', fake_uname, QL_INTERCEPT.EXIT)
```

### 3. Challenge3

Challenge3: /dev/urandom 和 getrandom 相等

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907141611-lvshawq.png)

程序需要使/dev/urandom 和 getrandom 相等，且一个字节的随机数和其他的随机数都不一样。

对 getrandom的劫持与Challenge2一样；对 /dev/urandom的劫持要用到 add\_fs\_mapper，add\_fs\_mapper可以实现将模拟环境中的路径劫持到主机上的路径或将读/写操作重定向到用户定义的对象。参考文档：https://docs.qiling.io/en/latest/hijack。

```python
class Fake_urandom(QlFsMappedObject):

    def read(self, size):
        if size == 1:
            return b'\x00'
        else:
            return b'\x01' * size

    def fstat(self):
        return -1

    def close(self):
        return 0


def challenge3(ql: Qiling):
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    ql.os.set_syscall('getrandom', fake_getrandom, QL_INTERCEPT.EXIT)
```

### 4. Challenge4

Challenge4: 进入禁止的循环

IDA F5识别流程有问题，查看汇编：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907145820-4fpx826.png)​

通过汇编可以看到，程序进入死循环，关键点在于控制判断结果。这里用到 hook_address 这个API，可以hook特定地址。注册的回调将在执行指定地址时被调用。参考文档：https://docs.qiling.io/en/latest/hook/。

通过 https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/linux.ql 可知 qiling 默认配置 linux64 加载基地址为 0x555555554000，cmp那条指令偏移是 0xFE0，hook_address 将 x0 改成比 x1 小即可。

```python
def stop(ql: Qiling) -> None:
    # ql.arch.regs.write("x1", 0)
    ql.arch.regs.write("x0", 1)


def challenge4(ql: Qiling):
    address = 0x555555554000 + 0xFE0
    ql.hook_address(stop, address)
```

### 5. Challenge5

Challenge5: 预测每次对rand的调用

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907174935-7u3bkfv.png)只要让每次 rand() 返回值等于0就可以。通过 ql.os.set\_api\(\) 就可以实现：

```python
def fake_rand(ql: Qiling, *args):
    ql.arch.regs.write("x0",0)


def challenge5(ql: Qiling):
    ql.os.set_api("rand", fake_rand)
```

但是没有显示 solved。。。

### 6. Challenge6

Challenge6: 避免无限循环

和 Challenge4 一样，看汇编：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907184004-9njlkko.png)

使 cmp 前使 x0=0，就可以跳出循环。

```python
def stop2(ql: Qiling) -> None:
    # ql.arch.regs.write("x1", 0)
    ql.arch.regs.write("x0", 0)


def challenge6(ql: Qiling):
    address = 0x555555554000 + 0x1118
    ql.hook_address(stop2, address)
```

challenge5 出现 solved 了，但是整个程序报错了。。。

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907190340-ux0j0bm.png)​

### 7. Challenge7

Challenge7: 不要浪费时间等待 sleep

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907191020-2139ekl.png)

劫持 sleep 函数，把 x0 改成 0 即可：

```python
def fake_sleep(ql: Qiling, *args):
    ql.arch.regs.write("w0", 0)


def challenge7(ql: Qiling):
    ql.os.set_api("sleep", fake_sleep)
```

一切恢复正常：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907192047-vkcop59.png)​

Challenge5 无回显应该是因为 Challenge6 存在死循环，Challenge6 接触死循环后 Challenge5 就正常了，但是由于修改了参数，导致 Challenge6 因为参数报错，劫持后修改参数，全部就正常了。

### 8. Challenge8

Challenge8: 在目标地址写入结构体

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220907195859-hpj8j3s.png)​

看代码，应该是结构体里套结构体，

结构应该如下：

```c
struct s1{
    struct *s2; // 8 bytes
    int num1+num2; // 8bytes
    int flag;    //8bytes
}

struct s2
{
    char buf[] = "Random data"
}
```

这里需要通过固定的 0x3DFCD6EA539 去找到结构体位置，进而修改 flag。qiling 提供了ql.mem.search用来搜索内存，但是实际搜索的时候发现会找到不止一个内存地址，且返回为 list：

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220908104343-3gmoe0e.png)​

因此还需要利用 Random data 进行比较。

参考文档：https://docs.qiling.io/en/latest/memory/

```python
def fake_nop(ql: Qiling):
    num = 0x3DFCD6EA00000539
    num_address_list = ql.mem.search(ql.pack64(num))
    for num_address in num_address_list:
        s1_address = num_address - 8
        s1 = ql.mem.read(s1_address, 0x18)
        s2_address, num2_addr, flag = struct.unpack('QQQ', s1)
        random_data = ql.mem.string(s2_address)
        if random_data == 'Random data':
            ql.mem.write(flag, b'\x01')
            break


def challenge8(ql: Qiling):
    address = 0x555555554000 + 0x11dc
    ql.hook_address(fake_nop, address)
```

### 9. Challenge9

Challenge9: 修改字符串操作

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220908114141-w1lfumi.png)

只要修改strcmp(src,dest) == 0 的结果就行，通过 os.set_api 劫持 strcmp即可：

```python
def fake_strcmp(ql: Qiling, *args):
    ql.arch.regs.write("x0", 0)


def challenge9(ql: Qiling):
    ql.os.set_api('strcmp', fake_strcmp)
```

### 10. Challenge10

Challenge10: 伪造成'cmdline' 文件来返回正确的内容

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220908115420-mq1h07p.png)

逻辑很简单，伪造 /proc/self/cmdline 这个文件，内容为"qilinglab" 即可。可以通过 os.set_api 劫持 strcmp，也可以通过 add_fs_mapper 映射到自定义实现或主机路径：

```python
class Fake_cmdline(QlFsMappedObject):

    def read(self, size):
        return b'qilinglab'

    def fstat(self):
        return -1

    def close(self):
        return 0


def challenge10(ql: Qiling):
    ql.add_fs_mapper("/proc/self/cmdline", Fake_cmdline())
    #ql.add_fs_mapper("/proc/self/cmdline", "/root/Desktop/cmdline")
```

### 11. Challenge11

Challenge11: Bypass CPUID/MIDR_EL1

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220908153835-1guz8ux.png)​

逻辑很简单，判断 x1 是否等于 x0，hook_address修改一下：

```python
def fake_end(ql: Qiling) -> None:
    ql.arch.regs.write("x1", 0x1337)


def challenge11(ql: Qiling):
    ql.hook_address(fake_end, 0x555555554000+ 0x1400)
```

## 0x02 EXP

![image](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220908155555-ve6ot43.png)​

```python
import struct

from qiling import *
from qiling.const import *
from qiling.os.mapper import QlFsMappedObject


# Challenge1
def challenge1(ql: Qiling):
    addr = 0x1337
    ql.mem.map(addr // 4096 * 4096, 0x1000)
    ql.mem.write(addr, ql.pack16(1337))


# Challenge2
def fake_uname(ql: Qiling, pName, *args):
    ql.mem.write(pName, b'QilingOS\x00')
    ql.mem.write(pName + 65 * 3, b'ChallengeStart\x00')


def challenge2(ql: Qiling):
    ql.os.set_syscall('uname', fake_uname, QL_INTERCEPT.EXIT)


# Challenge3
def fake_getrandom(ql: Qiling, pBuf, buflen, flag, *args):
    ql.mem.write(pBuf, b'\x01' * buflen)


class Fake_urandom(QlFsMappedObject):

    def read(self, size):
        if size == 1:
            return b'\x00'
        else:
            return b'\x01' * size

    def fstat(self):
        return -1

    def close(self):
        return 0


def challenge3(ql: Qiling):
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    ql.os.set_syscall('getrandom', fake_getrandom, QL_INTERCEPT.EXIT)


# Challenge4
def stop(ql: Qiling) -> None:
    # ql.arch.regs.write("x1", 0)
    ql.arch.regs.write("x0", 1)


def challenge4(ql: Qiling):
    address = 0x555555554000 + 0xFE0
    ql.hook_address(stop, address)


# Challenge5
def fake_rand(ql: Qiling, *args):
    ql.arch.regs.write("x0", 0)


def challenge5(ql: Qiling):
    ql.os.set_api("rand", fake_rand)


# Challenge6
def stop2(ql: Qiling) -> None:
    # ql.arch.regs.write("x1", 0)
    ql.arch.regs.write("x0", 0)


def challenge6(ql: Qiling):
    address = 0x555555554000 + 0x1118
    ql.hook_address(stop2, address)


# Challenge7
def fake_sleep(ql: Qiling, *args):
    ql.arch.regs.write("w0", 0)


def challenge7(ql: Qiling):
    ql.os.set_api("sleep", fake_sleep)


# Challenge8
def fake_nop(ql: Qiling):
    num = 0x3DFCD6EA00000539
    num_address_list = ql.mem.search(ql.pack64(num))
    for num_address in num_address_list:
        s1_address = num_address - 8
        s1 = ql.mem.read(s1_address, 0x18)
        s2_address, num2_addr, flag = struct.unpack('QQQ', s1)
        random_data = ql.mem.string(s2_address)
        if random_data == 'Random data':
            ql.mem.write(flag, b'\x01')
            break


def challenge8(ql: Qiling):
    address = 0x555555554000 + 0x11dc
    ql.hook_address(fake_nop, address)


# Challenge9
def fake_strcmp(ql: Qiling, *args):
    ql.arch.regs.write("x0", 0)


def challenge9(ql: Qiling):
    ql.os.set_api('strcmp', fake_strcmp)


# Challenge10
class Fake_cmdline(QlFsMappedObject):

    def read(self, size):
        return b'qilinglab'

    def fstat(self):
        return -1

    def close(self):
        return 0


def challenge10(ql: Qiling):
    ql.add_fs_mapper("/proc/self/cmdline", Fake_cmdline())


# Challenge11
def fake_end(ql: Qiling) -> None:
    ql.arch.regs.write("x1", 0x1337)


def challenge11(ql: Qiling):
    ql.hook_address(fake_end, 0x555555554000+ 0x1400)


if __name__ == "__main__":
    target = ['./qilinglab-aarch64']
    rootfs = "./arm64_linux"
    ql = Qiling(target, rootfs, verbose=QL_VERBOSE.DISABLED)
    challenge1(ql)
    challenge2(ql)
    challenge3(ql)
    challenge4(ql)
    challenge5(ql)
    challenge6(ql)
    challenge7(ql)
    challenge8(ql)
    challenge9(ql)
    challenge10(ql)
    challenge11(ql)
    ql.run()
```
