本文发表于 [冷月的博客](https://lengyue.me/2023/09/19/ntqq-db/), 基于 CC BY-NC-SA 4.0 共享.

## 0. 引言

为了让每个人都可以把自己练入 LLM, 制作自己的数字分身. 解析 QQ 数据库无疑是快速获得语料库的最佳途径. 然而, 众所周知, QQ 的数据库是加密的 SQLite 数据库, 且不幸的是, 在最新的 NTQQ 中数据库的加密方式已经发生了变化. 本文将介绍如何解析 Mac 的 NTQQ 数据库.

参考资料 (win): [Young-Lord/qq-win-db-key](https://github.com/Young-Lord/qq-win-db-key/blob/master/nt%20qq%20win%20db%20%E6%95%99%E7%A8%8B.md)

该方案于 2023 年 9 月 19 日在 NTQQ 6.9.17 上测试通过. 严禁用于非法用途.

## 1. 准备工作

在开始解析之前, 我们需要准备一些工具:

- [NTQQ](https://im.qq.com/macqq/index.shtml)
- [DB Browser for SQLite](https://sqlitebrowser.org/dl/)
- LLDB (MacOS 自带, 注意需要关闭 SIP)
- [Hopper Disassembler](https://www.hopperapp.com/download.html)

因为我们的流程非常简单, 免费版的 Hopper 即可满足需求.

## 2. 分析

你需要先准备一个自己喜欢的工作目录, 并且将 NTQQ 的 Library 复制到当前目录下:

```bash
cp /Applications/QQ.app/Contents/Resources/app/wrapper.node .
```

随后, 你需要使用 Hopper 打开 `wrapper.node` 在 Mac M1/M2 上需要选择 `aarch64`, 并且搜索 `nt_sqlite3_key_v2`.

<img src="https://imagedelivery.net/5O09_o54BtxkkrL59wq3ZQ/30dcc60b-3e3a-429d-c6cb-0428e0d41400/public" alt="Search" width="70%" />
<img src="https://imagedelivery.net/5O09_o54BtxkkrL59wq3ZQ/3aad8d0d-81d6-4a8d-a071-603d28579a00/public" alt="References to" width="50%" />
<img src="https://imagedelivery.net/5O09_o54BtxkkrL59wq3ZQ/a4cf0faa-b8c0-43d4-f52a-c074b32be700/public" alt="References to" width="50%" />

如上图所示, 我们可以跳转到引用该函数的地方, 随后记下该函数地址:

<img src="https://imagedelivery.net/5O09_o54BtxkkrL59wq3ZQ/0815717b-de37-4172-422f-fddcb6ed9500/public" alt="Address" width="70%" />

## 3. 断点 & 调试

随后我们运行 NTQQ, 找到它的进程 ID, 并且使用 LLDB 进行调试:

```bash
❯ ps aux | grep QQ
user          78488   1.5  0.5 1584651520 162000   ??  S     1:59PM   0:00.61 /Applications/QQ.app/Contents/MacOS/QQ
```

```bash
lldb -p 78488
```

我们需要寻找 `wrapper.node` 的加载地址:

```bash
(lldb) image list -o -f | grep /Applications/QQ.app/Contents/Resources/app/wrapper.node
[  0] 0x0000000110088000 /Applications/QQ.app/Contents/Resources/app/wrapper.node
```

接下来进行一个简单的数学运算, 计算出 `nt_sqlite3_key_v2` 的地址:

```bash
(lldb) expr 0x0000000110088000 + 0x000000000192bef8
(unsigned long) $0 = 4590354168
```

设置断点并且继续运行:

```bash
(lldb) br s -a 4590354168
Breakpoint 1: where = wrapper.node`___lldb_unnamed_symbol287604, address = 0x00000001119b3ef8

(lldb) c
Process 78488 resuming
```

点击登录后, 如无意外, 你会看到断点被命中, 并且进入了 `nt_sqlite3_key_v2` 函数, 如下图所示:

<img src="https://imagedelivery.net/5O09_o54BtxkkrL59wq3ZQ/ef93eb4b-3d67-46fb-90ce-48f8a3f5f300/public" alt="breakpoint" width="70%" />

参考函数签名:

```c
int sqlite3_key_v2(
  sqlite3 *db,                   /* Database to be keyed, x0 */
  const char *zDbName,           /* Name of the database, x1 */
  const void *pKey, int nKey     /* The key, x2, x3 */
);
```

接下来解析 16 个字符即可:

```plaintext
(lldb) register read x2
      x2 = 0x0000012801b34010

(lldb) memory read --format c --count 16 --size 1 0x0000012801b34010
0x12801b34010: L7LA=idk17,fn~uk
```

至此, 我们已经成功解析出了 NTQQ 的数据库密钥.

## 4. 解密

数据库位于 (注意 MD5 可能会随着 QQ 的版本更新而改变):

```plaintext
/Users/user/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/nt_qq_{MD5}/nt_db
```

复制你需要的文件, 如 `profile_info.db`:

```bash
cp "/Users/user/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/nt_qq_cc067b8bcbf8980fabd93574e09d9efa/nt_db/profile_info.db" test.db
```

对于解密数据库, 请参考 [基础教程 - NTQQ 解密数据库](基础教程 - NTQQ 解密数据库.md).

出于隐私考虑, 不展示解密后的数据库内容.

## 5. 总结

本文介绍了如何解析 NTQQ 的数据库, 以及如何使用 DB Browser for SQLite 浏览数据库.  
需要注意的是, 数据库结构仍需分析, 本文仅仅是提供了解密的方法.  
