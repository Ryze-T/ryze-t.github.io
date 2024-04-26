---
title: Sliver（二）：Armory
tags: Tools
---

Sliver提供了Armory这个功能，允许操作者通过添加基于第三方工具的新命令来扩展本地客户端控制台及其功能。通过Armory可以实现BOF 和 COFF 的加载和执行，安装的扩展只会在Client下生效，不会上传到服务端或同步到其他Client。

# Armory列表

[https://github.com/sliverarmory/armory/blob/master/armory.json](https://github.com/sliverarmory/armory/blob/master/armory.json)

# Armory操作

## 安装扩展

安装扩展通过`install`指令实现，安装时需要去github下载，为了方便墙内用户，Sliver也提供了-p参数。

![Untitled](https://raw.githubusercontent.com/Ryze-T/blog_picture/main/202404261555052.png)

从v1.5.14开始，可以通过`armory install all`直接安装所有官方扩展。

## 更新扩展

更新扩展通过`update`指令实现。它会更新所有已经安装的扩展。

![Untitled](https://raw.githubusercontent.com/Ryze-T/blog_picture/main/202404261555255.png)

## 删除扩展

删除扩展需要区分安装的扩展是alias还是extension，可以通过`aliases` 和`extensions` 命令查看扩展情况，然后再使用`aliases rm`和`extensions rm`来删除。

# 自定义BOF

Sliver同样提供了方法去帮助用户添加自己的BOF。

假设需要安装klist（查看缓存的Kerberos票据）时，可以下载https://github.com/Cyb3rC3lt/SliveryArmory/releases/tag/v1.0.0。压缩包中包含了source文件夹和extension.json。

首先在client机器上安装`mingw-w64` 和`make` ，进入source目录，执行`sudo make` ：

![Untitled](https://raw.githubusercontent.com/Ryze-T/blog_picture/main/202404261555642.png)

在上级目录底下生成了Klist.x64.o和Klist.x86.o（Extension.json文件中的Path需要修改成首字母大写）。

查看extension.json（此json文件在安装自定义BOF时需要自己编写）：

```jsx
{
    "name": "klist",
    "version": "1.0.0",
    "command_name": "klist",
    "extension_author": "Cyb3rC3lt",
    "original_author": "Cyb3rC3lt",
    "repo_url": "https://github.com/Cyb3rC3lt/SliverArmory/klistBOF",
    "help": "Displays a list of currently cached Kerberos tickets.",
    "long_help": "",
    "depends_on": "coff-loader",
    "entrypoint": "go",
    "files": [
        {
            "os": "windows",
            "arch": "amd64",
            "path": "Klist.x86.o"
        },
        {
            "os": "windows",
            "arch": "386",
            "path": "Klist.x86.o"
        }
    ],
    "arguments": [
        {
            "name": "purge",
            "desc": "Purge the cached Kerberos tickets.",
            "type": "wstring",
            "optional": true
        }
    ]
}
```

进入Sliver，执行`extensions install /home/kali/klist` ，随后在.sliver-client/extensions目录下可以看到klist文件夹。可以通过重启sliver-client或直接执行`extensions load /home/kali/.sliver-client/extensions/klist` 加载klist。

![Untitled](https://raw.githubusercontent.com/Ryze-T/blog_picture/main/202404261555246.png)