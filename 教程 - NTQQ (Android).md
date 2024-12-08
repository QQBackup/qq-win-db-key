# Android

## 注意

如果运行脚本时出现问题，请尝试将所有文件中的所有`libkernel`替换为`libbasic_share`。

## 方法1（推荐）

本方法不需要 root，只需要使用系统自带的备份功能导出 QQ 的数据即可。由于 QQ 限制，部分系统可能无法导出 QQ 数据，此时可以使用“聊天记录迁移”功能迁移到其他设备上。

经测试适用于`9.0.65`与`9.0.75`版本，更低版本可能无法使用此方法。

以下的`md5`函数返回结果均为 32 位，字符均为小写，在Python中等价于以下函数：`def md5(s): i=__import__('hashlib').md5();i.update(s.encode('utf8'));return i.hexdigest()`

为了方便起见，假设 QQ 号（表示为`uin`）为`390251789`，`uid`为`u_mIicAReWrdCB-kST6TXH7A`。

一切以`/data/user/0/com.tencent.mobileqq/`开头的路径均表示root后可以访问到的绝对路径，若为处理备份文件，则此路径可能有所不同。

### 获取uid

获取`uid`有多种方式，任意一种均可。

- 将`/data/user/0/com.tencent.mobileqq/databases/beacon_db_com.tencent.mobileqq`文件作为纯文本文件打开，查找你的 QQ 号对应的`uid`，形式如`"home_uin": "390251789","uid":"u_mIicAReWrdCB-kST6TXH7A"`，其中`u_mIicAReWrdCB-kST6TXH7A`即为`uid`。
- 在`/data/user/0/com.tencent.mobileqq/files/uid/`目录下，可见到文件名形如`390251789###u_mIicAReWrdCB-kST6TXH7A`的若干个文件，其中`u_mIicAReWrdCB-kST6TXH7A`即为`uid`。
- 若使用了[QAuxiliary](https://github.com/cinit/QAuxiliary)模块，可以通过打开`[辅助功能]聊天和消息-[消息]转发消息点头像查看详细信息`功能，合并转发由自己发送的消息，查看消息的`senderUid`属性获取，详见[#32](https://github.com/QQBackup/qq-win-db-key/issues/32#issue-2418610093)。

对`uid`取`md5`即可得到`QQ_UID_hash`（即`QQ_UID_hash = md5(uid) = md5("u_mIicAReWrdCB-kST6TXH7A") = "255c42fc0f4d295678e6ff0135fcf5dd"`）

### 获取聊天记录文件

聊天记录可在以下路径找到：

```plain
/data/user/0/com.tencent.mobileqq/databases/nt_db/nt_qq_{QQ_path_hash}/nt_msg.db
```

此处的`QQ_path_hash`有两种方法获得：

1. 猜测

    如果你登录的 QQ 账号数量不多，可以通过文件更新时间、文件大小等猜测。

2. 计算

    对`QQ_UID_hash`进行如下运算即可得到`QQ_path_hash`：`QQ_path_hash = md5(md5(uid) + "nt_kernel") = md5("255c42fc0f4d295678e6ff0135fcf5ddnt_kernel") = "b69bfb8e74137f4e4253d1af3e99493a"

    则聊天记录路径为`/data/user/0/com.tencent.mobileqq/databases/nt_db/nt_qq_b69bfb8e74137f4e4253d1af3e99493a/nt_msg.db`

### 获取密钥

使用`HxD`或者其他二进制查看工具打开`nt_msg.db`文件，将文件头部跟随在`QQ_NT DB`后的可读字符串复制，形如`6tPaJ9GP`，记为`rand`。

此时可以计算出数据库密钥`key`：`key = md5(QQ_UID_hash + rand) = md5("255c42fc0f4d295678e6ff0135fcf5dd6tPaJ9GP") = "71c0dfcef3b5ceae7c4a1c68ca662f4a"`。

则数据库密钥为`71c0dfcef3b5ceae7c4a1c68ca662f4a`。

另外，文件头部还可能含有`cipher_hmac_algorithm`的值（如`HMAC_SHA1`）等与解密相关的信息，可被解析为Protobuf数据，详见[#29 (comment)](https://github.com/QQBackup/qq-win-db-key/issues/29#issuecomment-2227660390)，此处不展开说明。

#### 打开数据库

请参考 [基础教程 - NTQQ 解密数据库](基础教程%20-%20NTQQ%20解密数据库.md)。

如果文件头中出现`HMAC_SHA1`字样（[示例](https://github.com/QQBackup/qq-win-db-key/issues/29#issuecomment-2227660390)），则将其作为`cipher_hmac_algorithm`的值。否则，可尝试`HMAC_SHA512`（默认值）或`HMAC_SHA256`。

## 方法2

此方法要求您拥有手机的 root 权限。

### 基础环境

以下环境配置任选一种即可。

#### Termux

首先，安装 Termux，换源并执行`pkg up`、`termux-setup-storage`

然后依次执行以下命令：

安装基础依赖：

```shell
pkg in python wget tsu root-repo
pkg in frida frida-python
```

关闭 SELinux：

```shell
su -c setenforce 0
```

接着，手动下载主版本相同的`frida-server`，解压到`/data/local/tmp`下，并重命名为`friendly`（不一定要完全一致，仅是建议文件名不包含`frida`以略微避免检测）；

赋予`friendly`可执行权限后，新开一个终端以`root`权限运行`friendly`

下载 hook 脚本：

```shell
wget https://github.com/QQBackup/qq-win-db-key/raw/master/android_get_key.py
```

#### PC

你也可以在电脑端使用`adb`等来避免在手机端配置`Termux`。具体过程略。

### 获取密钥

打开 QQ 并完成登录，进入主界面。将 QQ 切换到后台后继续下一步。

在 Termux 终端 / 电脑的终端 中运行：

```shell
python android_get_key.py
```

也可手动指定版本号，但目前所有支持的版本号使用的脚本均相同。

```shell
python android_get_key.py 8.9.58
```

此时应当输出`Frida script injected.`，若没有，请检查：

- 是否以`root`权限运行`frida-server`
- 是否以关闭 SELinux （即设置为宽容模式）
- 是否已经关闭`Magisk Hide`与`Shamiko`，并且重启手机
- `frida-server`与 Termux 中的`frida`版本号第一个点号前的数字是否相同
- QQ 版本是否一致

接下来，可以确认命令行是否给出数据库密钥（以`pKey`显示）。

### 打开数据库

请参考 [基础教程 - NTQQ 解密数据库](基础教程%20-%20NTQQ%20解密数据库.md)。

## 方法3

此方法同样要求您拥有手机的 root 权限，环境配置与[方法2](#方法2)相同。不同之处在于，本方法可以直接导出解密后的数据库文件，而无需额外修复与解密。

> 该部分内容来源于[Android QQ NT 版数据库解密](https://blog.yllhwa.com/2023/09/29/Android%20QQ%20NT%20%E7%89%88%E6%95%B0%E6%8D%AE%E5%BA%93%E8%A7%A3%E5%AF%86/)，由[@yllhwa](https://github.com/yllhwa)贡献。

关闭`Magisk Hide`与`Shamiko`，并且重启手机

可能需要关闭`SELinux`（也就是设为`Permissive`）

需要授予手机QQ读写存储权限

下载`https://github.com/QQBackup/qq-win-db-key/raw/master/android_dump.js`

如果先前已经运行过，则先删除上一次运行生成的`/sdcard/Download/plaintext.db`

终端中运行`frida -U -f com.tencent.mobileqq -l android_dump.js`（如果用的有线连接adb就直接写`-U`，如果是Termux或无线连接就把`-U`改成`-R`）

如果一切顺利，已解密的`plaintext.db`将会在至少5秒后导出至`/sdcard/Download/plaintext.db`。
