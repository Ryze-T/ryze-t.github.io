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
