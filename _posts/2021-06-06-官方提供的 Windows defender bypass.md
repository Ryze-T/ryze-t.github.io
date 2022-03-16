---
title: 官方提供的 Windows defender bypass
tags: bypass
---

# 官方提供的 Windows defender bypass

## 官方文档

在制作免杀的过程中，翻找 Windows 官方对 Windows Defender 的介绍，发现有这样一个目录：[Configure Microsoft Defender Antivirus exclusions on Windows Server](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-server-exclusions-microsoft-defender-antivirus?view=o365-worldwide#list-of-automatic-exclusions)（在 Windows server 中配置defender排除项）。

![image-20210607090532668](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210607090532668.png)

简而言之就是在 Windows Server2016 和 2019 中，Windows Defender 默认存在一些排除项，在实时检测过程中会忽略这些排除项，但是主动扫描的时候不会排除。这就给 Bypass Windows Defender 提供了一个新思路。

通篇寻找可用的路径，最终发现几个 exe 路径：

| 路径                                   | 用途               |
| -------------------------------------- | ------------------ |
| %systemroot%\System32\dfsr.exe         | 文件复制服务       |
| %systemroot%\System32\dfsrs.exe        | 文件复制服务       |
| %systemroot%\System32\Vmms.exe         | Hyper-V 虚拟机管理 |
| %systemroot%\System32\Vmwp.exe         | Hyper-V 虚拟机管理 |
| %systemroot%\System32\ntfrs.exe        | AD DS 相关支持     |
| %systemroot%\System32\lsass.exe        | AD DS 相关支持     |
| %systemroot%\System32\dns.exe          | DNS 服务           |
| %SystemRoot%\system32\inetsrv\w3wp.exe | WEB服务            |
| %SystemRoot%\SysWOW64\inetsrv\w3wp.exe | WEB服务            |
| %SystemDrive%\PHP5433\php-cgi.exe      | php-cgi 服务       |

在文件路径不冲突的情况下，将这10个路径的木马应当都具有 bypass Windows Defender 的效果。

## 实例

以最后一个 php-cgi.exe 为例，默认在 Windows Server 2019 中是没有此路径的，所以在实际使用过程中需新建此目录。

首先使用 msf 生成一个默认的 exe 木马，并下载到目标服务器中执行，发现 Windows Defender 发出警告：

![image-20210607090603451](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210607090603451.png)

获得的 session 也是昙花一现：

![image-20210607090615924](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210607090615924.png)

新建 php5433 目录，并将木马更名为 php-cgi.exe，执行：

![image-20210607090640429](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210607090640429.png)



木马正常上线：

![image-20210607090648883](https://gitee.com/tboom_is_here/pic/raw/master/img/image-20210607090648883.png)