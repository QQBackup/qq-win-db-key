参考了 <https://github.com/QQBackup/QQ-History-Backup/issues/9> 以及 <https://github.com/QQBackup/qq-win-db-key> 中的各平台教程。

## I 环境配置

### 越狱环境

可参考 [Frida 文档 - With Jailbreak](https://frida.re/docs/ios/#with-jailbreak)

在 iOS 设备上操作

~1. Cydia / Sileo / Zebra 添加 Frida 官方软件源 `https://build.frida.re`~

> [!Important]
> 由于自 Frida 17.0.0 开始，`Module.findBaseAddress()` 被移除， \
> 因此安装的是老版本，否则执行脚本将报错 `TypeError: not a function` \
> 更新日志：https://frida.re/news/2025/05/17/frida-17-0-0-released/


1. 前往 [Frida Release 16.7.19](https://github.com/frida/frida/releases/tag/16.7.19) 下载 Frida
    - 下载 `frida_17.2.17_iphoneos-arm64.deb`（有根越狱则 `frida_17.2.17_iphoneos-arm.deb`）

2. 用 Cydia / Sileo / Zebra 安装上一步下载好的安装包

3. 启动 Frida 服务器

在终端（NewTerm 之类的终端App，或SSH）运行：

```sh
frida-server -v
```

如果端口被占用，更换其他端口，如：

```sh
frida-server --listen='0.0.0.0:27043' -v
```

启动 Frida 服务端。

> 命令前部加上 `sudo` 赋予 root 用户权限也许会更好

### 免越狱环境

- 需要有 **TrollStore 巨魔** 环境
  - 安装教程：[cfw iOS Guide - Installing TrollStore](https://ios.cfw.guide/installing-trollstore/)

- 参考链接：[Frida 文档 - Without Jailbreak](https://frida.re/docs/ios/#without-jailbreak)

#### 开始

1. App 脱壳，可参考[下一章节](#app-脱壳)（需要得到完整的 IPA 安装包）

> [!Important]
> 由于自 Frida 17.0.0 开始，`Module.findBaseAddress()` 被移除， \
> 因此安装的是老版本，否则执行脚本将报错 `TypeError: not a function` \
> 更新日志：https://frida.re/news/2025/05/17/frida-17-0-0-released/

2. 下载 Frida Gadget 动态链接库 **`frida-gadget-x.x.x-ios-universal.dylib.gz`** \
并解压得到 `frida-gadget-ios-universal.dylib`
   - [Frida Release 16.7.19](https://github.com/frida/frida/releases/tag/16.7.19)

3. 注入 Frida Gadget 动态链接库，有两种方法，Sideloadly 更方便且支持 Windows，命令行方式 optool 需要在 macOS 环境下进行

#### 方式一、使用 Sideloadly 注入 Frida Gadget

直接照图进行配置：

- 不允许自动更改 Bundle ID
- 开启文件共享（即开放 App 沙盒 Documents 目录到系统自带的文件 App）
- 注入动态链接库
- 仅导出 IPA

然后点击 Start 开始导出

![Sideloadly 中的具体配置选项](img/image-ios-5.webp)

#### 方式二、使用 optool 注入 Frida Gadget

1. 解压脱壳得到的 IPA 安装包

2. 安装 optool，这里需要使用 `xcodebuild` 命令

```sh
git clone https://github.com/alexzielenski/optool.git
cd optool
git submodule update --init --recursive
xcodebuild
ln -s $PWD/build/Release/optool /usr/local/bin/optool
```

3. 将前面下载的 **`frida-gadget-ios-universal.dylib`** 放入 IPA 解压目录下的 `Payload/QQ.app/Frameworks` 目录

```sh
cp frida-gadget-ios-universal.dylib Payload/QQ.app/Frameworks
```

4. 用 optool 把动态链接库加载命令插入到 QQ 主程序中（此处路径无法自动补全，注意不要打错了）

```sh
optool install -c load -p "@executable_path/Frameworks/frida-gadget-ios-universal.dylib" -t Payload/QQ.app/QQ
```

运行成功的输出：

```plaintext
Found thin header...
Load command already exists
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/QQ.app/QQ...
```

5. 为了方便后续导出聊天记录数据库等文件，需要修改 App 配置，允许用户通过系统自带的文件 App 访问 App 沙盒 Documents 目录，具体操作可以网上查询（

6. 重新打包 IPA，可以直接压缩 `Payload` 目录为 zip 归档，然后重命名文件后缀为 `ipa`，把重新打包好的 IPA 安装包发送到 iOS 设备

#### 安装重新打包好的 IPA

发送重新打包好的 QQ IPA 安装包到 iOS 设备，**使用 TrollStore 巨魔** 进行安装，如果提示安装失败，应用已存在，选择强制安装

> 需要使用巨魔的原因：附带了 Frida Gadget 的 QQ 安装包需要以覆盖，或者更新的方式安装到设备，这样它才能读取到聊天记录，不然系统会分配新的沙盒空间。为了实现这一点，App Bundle ID 需要保持不变，即 `com.tencent.mqq`，但如果使用腾讯的 `com.tencent.*` 作为 Bundle ID，在签名过程中就会失败，因此需要绕过签名，即使用 TrollStore 安装。

将 iOS 设备有线连接至 PC，可以自行用 `frida-ps` 等工具测试一下 Frida 服务器是否正常工作（无线连接等可以参考 [Frida 文档 - Gadget](https://frida.re/docs/gadget/)）

## II 反编译

如果你的 QQ 版本和脚本 [ios_get_key.js](ios_get_key.js) 内注释的版本一致，可直接跳过进入下一步

如果 QQ 版本不一致，但下一步的脚本 [ios_get_key.js](ios_get_key.js) 可以正常使用，也可以忽略本节

### App 脱壳

可选工具

- dumpdecrypted (<https://github.com/stefanesser/dumpdecrypted>)
- frida-ios-dump (<https://github.com/AloneMonkey/frida-ios-dump>)
- AppsDump2（有图形界面的App，用起来很方便，不过似乎找不到它的仓库链接）
   ![AppsDump2](img/image-ios-4.webp)
- ...

只需要得到脱壳后的 Mach-O 二进制主程序即可，不需要完整的 IPA 安装包。

### 反编译

本篇示例

- iOS QQ v9.0.1.620
- SQLCipher v4.5.1

**主要目的是获取 `sqlite3_key_v2` 函数位置**，页大小、纯文本文件大小、PBKDF2 迭代次数等通常是固定的。

1. 用例如 IDA 的反编译工具反编译脱壳得到的 Mach-O 二进制主程序

2. 搜索二进制片段 `sqlite3_key_v2`，可以找到日志文本，从而定位到SQLCipher C API 的 `sqlite3_key_v2` 函数在程序中的位置。第三个参数即为数据库密钥，根据传入的其他实参，还能得到更多信息
    - 右键 - 点击“List cross references to...” 即可查找引用

> [!Note]
> 如果没有找到引用 `sqlite3_key_v2` 的代码，一般是因为 IDA 尚未解析完整个二进制程序，可以静默等待其处理一段时间后再尝试

```c
int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey);
```

> <https://github.com/sqlcipher/sqlcipher/blob/2c672e7dd1f3dee4aa1af0b5bf29092db4b10f78/src/crypto.c#L919-L928>

得到目标函数的位置为 `000000010DA1BFB4`。由于IDA基址设为了 `0000000100000000`，两者相减，\
**得到偏移量为 `0xDA1BFB4`，将其设置为脚本文件 [ios_get_key.js](ios_get_key.js)  中的 `SQLLiteKeyV2Offset` 的值**。

```javascript
// ios_get_key.js
const SQLLiteKeyV2Offset = 0xDA1BFB4;
```

![sqlite3_key_v2 函数在 IDA 中的汇编代码与伪代码](img/image-ios-1.webp)

3. 根据调用关系 `sqlite3CodecAttach`->`sqlcipher_codec_ctx_init`->`sqlcipher_codec_ctx_set_pagesize` 可以确定页大小为 `4096`

![在 IDA 中分析 sqlcipher_codec_ctx_set_pagesize 的调用关系](img/image-ios-3.webp)

4. 根据调用关系  \
`sqlite3CodecAttach`->`sqlcipher_codec_ctx_init`->`sqlcipher_codec_ctx_set_plaintext_header_size`，\
用 Frida hook `sqlcipher_codec_ctx_set_plaintext_header_size` 函数，可以确定纯文本文件大小为 `0`

![在 IDA 中分析 sqlcipher_codec_ctx_set_pagesize 的调用关系](img/image-ios-2.webp)

## III Frida 附加到 QQ 进程，获取密钥

1. **在 PC 上安装** frida（确保 Python 已安装）

```bash
# pipx 可以把包安装到隔离的环境，避免依赖冲突
pip install pipx
pipx install frida-tools==13.7.1
```

> [!Important]
> 同上，由于自 Frida 17.0.0 开始，`Module.findBaseAddress()` 被移除， \
> 因此安装的是老版本 Frida，包括 PC 上作为客户端的 frida-tools \
> 更新日志：https://frida.re/news/2025/05/17/frida-17-0-0-released/

2. 下载 [ios_get_key.js](ios_get_key.js)（如果上一步已经下载过了可以跳过）

3. iOS 设备打开 QQ App

4. **PC Frida** 连接至 iOS 设备，终端运行命令以附加脚本到 QQ 进程

连接方式有两种：

- USB 连接：

```shell
frida -U QQ -l ios_get_key.js
```

- 网络连接

```shell
frida -H <设备IP地址>:<frida-server端口号> QQ -l ios_get_key.js
```

IP地址为iOS设备的IP地址，端口号在[第一步](#越狱环境)配置过。例如：

```shell
frida -H 192.168.1.163:27043 QQ -l ios_get_key.js
```

> iOS frida-server 只能附加到已有进程，不能以 spawn 方式生成进程，原因暂不知

5. iOS 设备 QQ 进行登录操作

6. 查看 **PC 终端** 输出内容，可以看到一条条信息被输出，其中

- **`pKey` 为数据库密钥**
- **`zFilename` 为对应的数据库文件所在路径**

输出的数据库信息已经过筛选。

例如：

```plaintext
+------------
¦- db: 0x152ec8710
¦- *zDb: main
¦- *pkey: d3c1d0f05b2cxxxxxxxxxxc1ac161c29
¦- *pkey-hex: ...
¦- nKey: 32
¦+
¦- zFilename: /var/mobile/Containers/Data/Application/22675923-xxxx-xxxx-xxxx-C1CB389E8E22/Documents/QQNT/DB/nt_db/nt_qq_15207xxxxxxxxxxxxxxxxx0d0be/nt_msg.db
+------------
¦- db: 0x152ec8710
¦- *zDb: main
¦- *pkey: d3c1d0f05b2cxxxxxxxxxxc1ac161c29
¦- *pkey-hex: ...
¦- nKey: 32
¦+
¦- zFilename: /var/mobile/Containers/Data/Application/22675923-xxxx-xxxx-xxxx-C1CB389E8E22/Documents/QQNT/DB/nt_db/nt_qq_15207xxxxxxxxxxxxxxxxx0d0be/guild_msg.db
+------------
```

**复制其中的 `pKey` 和 `zFilename`**

7. 从 iOS 设备下载数据库文件
    - 越狱用户可使用 SFTP 或 Filza App
    - 免越狱方式直接用 iOS 自带的文件 App 查看

路径为上一步的 `zFilename` 所在目录的路径

```plaintext
/var/mobile/Containers/Data/Application/22675923-xxxx-xxxx-xxxx-C1CB389E8E22/Documents/QQNT/DB/nt_db/nt_qq_15207xxxxxxxxxxxxxxxxx0d0be
```

该目录下有数个数据库，除了一般的聊天记录以外还有（QQ频道记录？）更多数据。

8. 打开数据库

请参考 [基础教程 - NTQQ 解密数据库](基础教程%20-%20NTQQ%20解密数据库.md)。

