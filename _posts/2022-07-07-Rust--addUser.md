---
title: Rust--addUser
tags: tools
---
## 0x00 前言
偶然得知微软官方发布了Rust for Windows（https://github.com/microsoft/windows-rs），Rust可以直接原生调用任何Windows API，极大的扩展了 rust 在 windows 上的开发范围和能力。
因此尝试使用 Rust 编写一个添加管理员的 Rust 应用。
项目地址：https://github.com/Ryze-T/rust-addUser

## 0x01 构建
之前用C写过，因此知道添加管理员需要使用到两个api：NetUserAdd 和 NetLocalGroupAddMembers，同时需要两个结构体：USER_INFO_1 和 LOCALGROUP_MEMBERS_INFO_3。

### 1.1 NetUserAdd
函数定义：
```rust
pub unsafe fn NetUserAdd<'a, Param0: IntoParam<'a, PCWSTR>>(
    servername: Param0, 
    level: u32, 
    buf: *const u8, 
    parm_err: *mut u32
) -> u32
```

具体参数含义还需要去微软官方搜索对应 API 查看：

+ servername 为 NULL 时代表本地计算机。

+ level 为 1 时，指定有关用户参数的信息，此时 buf 参数指向 USER_INFO_1结构。
+ parm_error 指向一个值的指针，为 NULL 时 在出错时不返回索引。

servername 的类型为 Param0，即 IntoParam<'a, PCWSTR>，而且 rust 中并没有 NULL，因此这里定义为：

```rust
let servename = PCWSTR::default();
```

USER_INFO_1 结构体定义：

```rust
pub struct USER_INFO_1 {
    pub usri1_name: PWSTR,
    pub usri1_password: PWSTR,
    pub usri1_password_age: u32,
    pub usri1_priv: USER_PRIV,
    pub usri1_home_dir: PWSTR,
    pub usri1_comment: PWSTR,
    pub usri1_flags: USER_ACCOUNT_FLAGS,
    pub usri1_script_path: PWSTR,
}
```

不一一解释，重点关注 usri1_name 和 usri1_password，这两个参数指明添加用户的账号密码。但是其类型是 PWSTR，查看该类型定义：

```rust
pub struct PWSTR(pub *mut u16);
```

因此获取字符串的指针后，强制类型转换为 u16，再转为 PWSTR。

这里还涉及到 rust 与 Windows 编码的问题，rust 本机字符串默认是 UTF-8，而许多 Windows 函数都以 UTF-16 作为字符串编码，因此如果 username 或 password 在定义时没有转为 utf-16，实际添加的用户在 Windows 上就会出现乱码。因此可以使用 encode_utf16()，将字符串转为 utf16 值的迭代器，通过 collect() 在该迭代器上构造一个 Vec\<u16>，再 push(0) 作为字符串结尾。

因此代码为：

```rust
let mut username: Vec<u16> = "test".encode_utf16().collect();
username.push(0);
let p_username = username.as_ptr() as *mut u16;

let mut password: Vec<u16> = "1q@W3e$r".encode_utf16().collect();
password.push(0);
let p_password = password.as_ptr() as *mut u16;

let ui1 = &mut USER_INFO_1{
    usri1_name:PWSTR(p_username),
    usri1_password:PWSTR(p_password),
	usri1_password_age: 0,
	usri1_priv: USER_PRIV_USER,
	usri1_home_dir: PWSTR(std::ptr::null_mut()),
	usri1_comment: PWSTR(std::ptr::null_mut()),
	usri1_flags: UF_SCRIPT,
	usri1_script_path: PWSTR(std::ptr::null_mut()),
};
```

由于 buf 的参数类型为 *const u8，因此在调用时要使用 as 作为强制类型转换。

最后进行 NetUserAdd 调用：

```
NetUserAdd(servename,level,ui1 as *const _ as _,parm_error );
```

### 1.2 NetLocalGroupAddMembers

NetLocalGroupAddMembers 是用来将用户加入到特定组的 Windows API，其函数定义为：

```rust
pub unsafe fn NetLocalGroupAddMembers<'a, Param0: IntoParam<'a, PCWSTR>, Param1: IntoParam<'a, PCWSTR>>(
    servername: Param0, 
    groupname: Param1, 
    level: u32, 
    buf: *const u8, 
    totalentries: u32
) -> u32
```

了解了上一个 api 在 rust 中的表现形式之后，这个 api 也就不难了，要注意的两个参数：groupname 和 buf，buf指向的是  LOCALGROUP_MEMBERS_INFO_3。

groupname 和 servername 一样，但是这里需要赋值，因此也要和 USER_INFO_1 中的 usri1_username 一样处理：

```rust
let mut groupname: Vec<u16> = "administrators".encode_utf16().collect();
groupname.push(0);
let p_groupname = groupname.as_ptr() as *mut u16;
```

LOCALGROUP_MEMBERS_INFO_3 结构体定义：

```rust
pub struct LOCALGROUP_MEMBERS_INFO_3 {
    pub lgrmi3_domainandname: PWSTR,
}
```

这里的 lgrmi3_domainandname 指用户名，因此用 p_username 即可。

最后调用为：

```rust
NetLocalGroupAddMembers(servename,PCWSTR(p_groupname),3,lmi3 as *const _ as _,1);
```

## 0x02 结果

![image-20220707132216222](https://ryze-1258886299.cos.ap-beijing.myqcloud.com/image-20220707132216222.png)