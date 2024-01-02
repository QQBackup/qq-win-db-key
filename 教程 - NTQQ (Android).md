# Android

## 基础环境

以下环境配置任选一种即可。

### Termux

首先，安装 Termux，换源并执行`pkg up`、`termux-setup-storage`

然后依次执行以下命令：

安装基础依赖：

```shell
pkg in python wget tsu
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
wget https://github.com/Young-Lord/qq-win-db-key/raw/master/android_get_key.py
```

### PC

你也可以在电脑端使用`adb`等来避免在手机端配置`Termux`。具体过程略。

## 开跑

> 这几条并不需要按顺序执行，建议直接执行“导出数据库”

### 获取数据库密钥

打开 QQ 并完成登录，进入主界面。将 QQ 切换到后台后继续下一步。

在一个没有获得 root 权限的 Termux 终端 / 电脑的终端 中运行：

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

接下来，可以确认命令行是否给出数据库密钥。

### 使用 SQLiteStudio 打开数据库（未测试，可能过时）

删除nt_msg.db文件的前1024字节数据

使用SQLiteStudio打开处理后的nt_msg.db文件

数据库类型选 SQLCipher

密码（密钥）为空，通过PRAGMA设置密钥

加密算法配置（可选）输入以下内容：

```shell
PRAGMA key = 'pass';    -- pass 替换为之前得到的密码（32字节md5小写字符串）
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 4000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;
PRAGMA cipher = 'aes-256-cbc';
```

### 导出数据库

> 该部分内容来源于[Android QQ NT 版数据库解密](https://blog.yllhwa.com/2023/09/29/Android%20QQ%20NT%20%E7%89%88%E6%95%B0%E6%8D%AE%E5%BA%93%E8%A7%A3%E5%AF%86/)，由[@yllhwa](https://github.com/yllhwa)贡献。

关闭`Magisk Hide`与`Shamiko`，并且重启手机

可能需要关闭`SELinux`（也就是设为`Permissive`）

需要授予手机QQ读写存储权限

下载`https://github.com/Young-Lord/qq-win-db-key/raw/master/android_dump.js`

如果先前已经运行过，则先删除上一次运行生成的`/sdcard/Download/plaintext.db`

终端中运行`frida -U -f com.tencent.mobileqq -l android_dump.js`（如果用的有线连接adb就直接写`-U`，如果是Termux或无线连接就把`-U`改成`-R`）

如果一切顺利，已解密的`plaintext.db`将会在至少10秒后导出至`/sdcard/Download/plaintext.db`。

## 失败记录

根据字符串依次找到 sqlite3CodecQueryParameters，xref 找到 attachFunc，另外一个 xref 就是 openDatabase

"ATTACH DATABASE '%s' as migrate;" 之类的找到 sqlcipher_codec_ctx_migrate，然后找到 sqlite3_exec，执行：`ATTACH DATABASE 'plaintext.db' AS plaintext KEY '';SELECT sqlcipher_export('plaintext');DETACH DATABASE plaintext;` …然后你就能被附加数据库数量限制拦了。

VACUUM？不行

别的什么方法也失败了（详见代码
