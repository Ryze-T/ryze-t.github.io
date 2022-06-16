---
title: Windows Defender Bypass
tags: Bypass
---

# Windows Defender Bypass

## Server 

特殊目录Bypass

参考https://ryze-t.com/2021/06/06/%E5%AE%98%E6%96%B9%E6%8F%90%E4%BE%9B%E7%9A%84-Windows-defender-bypass/

## PC

参考 https://github.com/plackyhacker/Shellcode-Encryptor的思路。

代码均以上传至github：

分为两个步骤：shellcode加密和加载器执行。

### shellcode 加密

流程如下：

![image-20220616173139230](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616173139230.png)

通过脚本得到执行结果：

![image-20220616162742100](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616162742100.png)

### 加载器执行

分配完可读可写可执行内存后，利用C#的委托特性执行。

流程如下：

![image-20220616174029183](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616174029183.png)

复制 Key 和 Encrypted shellcode 到准备好的进程注入C#代码中，生成exe即可。

![image-20220616180511383](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/20220616180511.png)

### 效果

![image-20220616174505066](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616174505066.png)

![image-20220616174411311](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616174411311.png)

![image-20220616174605040](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616174605040.png)

![image-20220616174834832](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220616174834832.png)

