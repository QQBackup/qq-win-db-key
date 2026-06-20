# 教程 - NTQQ (macOS ARM，无需关闭 SIP)

> **测试环境**：QQ NT 6.9.96，macOS 26 Sequoia / macOS 27 Tahoe（Apple Silicon，arm64）
>
> **与[原 ARM 教程](教程%20-%20NTQQ%20(macOS%20ARM).md)的区别**：原教程要求关闭 SIP，在 macOS 14+ 上关闭 SIP 操作繁琐，macOS 27 早期开发者测试版更存在 `csrutil disable` 无效的已知 bug。本教程**无需关闭 SIP**，也无需 Hopper 等付费反汇编工具，全程使用系统自带工具和 Python 标准库。

---

## 0. 原理

QQ NT 的 `wrapper.node`（一个 Electron native module）内部静态链接了 SQLCipher，并通过内部函数 `nt_sqlite3_key_v2` 向 SQLite 数据库传递密钥。该函数在 **QQ 首次打开数据库时**（即点击登录后）被调用，此时密钥以明文形式存在于 `x2` 寄存器中。

lldb 默认无法 attach 到带有 hardened runtime + library validation 的 QQ 进程。**解决方案**：用 ad-hoc 签名重新签名 QQ，绕过该限制，无需关闭 SIP。

---

## 1. 准备工作

只需系统自带工具：

- **lldb**（Xcode Command Line Tools 自带）
- **Python 3**（macOS 自带）
- 安装 sqlcipher：`brew install sqlcipher`

---

## 2. Ad-hoc 重新签名 QQ（绕过 lldb attach 限制）

```bash
# 移除原签名，用 ad-hoc 签名替代（不需要开发者证书）
sudo codesign --remove-signature /Applications/QQ.app
sudo codesign --force --deep --sign - /Applications/QQ.app
```

> **说明**：`-s -` 表示 ad-hoc 签名（系统生成的伪签名）。QQ 大部分功能正常，可能偶尔提示"QQ 已被修改"，忽略即可。重新签名信息存储在二进制文件里，Mac **重启后无需重新签名**，重装 QQ 后需要重新执行一次。

---

## 3. 下载脚本

本教程配套三个脚本，位于仓库 `scripts/macos-arm-nosip/` 目录：

| 文件 | 用途 |
|---|---|
| `qq_web.py` | **一键 GUI 工具**（最推荐）：自动检测签名、备份数据库、提取密钥、导出聊天记录，全程点击操作 |
| `find_key_func.py` | 独立 VA 分析工具（命令行打印地址） |
| `qq_key_extractor.py` | lldb 自动化模块（全自动：自动设断点、自动打印密钥）；**已内嵌在 `qq_web.py` 中**，单独使用时才需要下载 |

```bash
# 只需下载 qq_web.py 即可（推荐）
curl -sO https://raw.githubusercontent.com/QQBackup/qq-win-db-key/master/scripts/macos-arm-nosip/qq_web.py

# 若需要命令行脚本，额外下载：
curl -sO https://raw.githubusercontent.com/QQBackup/qq-win-db-key/master/scripts/macos-arm-nosip/find_key_func.py
curl -sO https://raw.githubusercontent.com/QQBackup/qq-win-db-key/master/scripts/macos-arm-nosip/qq_key_extractor.py
```

---

## 4. 提取密钥

### 方式 0：GUI 一键工具（最推荐）

下载 `qq_web.py` 后，只需一条命令：

```bash
pip3 install flask && python3 qq_web.py
```

浏览器自动打开 `http://127.0.0.1:8899`，按页面步骤操作：

1. **第一步 - 重新签名**：若 QQ 已是 ad-hoc 签名则自动跳过；否则点击按钮，工具会先备份数据库再重新签名。
2. **第二步 - 提取密钥**：点击"启动 QQ + 注入 lldb"，然后在 QQ 界面点击登录（或随便点一条聊天消息），密钥自动显示。
3. **第三步 - 导出数据**：填写导出路径，一键导出为 HTML 聊天记录。

> **注意**：`qq_key_extractor.py` 已内嵌在 `qq_web.py` 中，无需单独下载。

---

### 方式 A：命令行全自动

使用 `qq_key_extractor.py`，全程只需 5 条命令，密钥自动打印。

**先关闭 QQ**，然后打开两个终端：

**终端 A**（先执行）：

```bash
lldb -n QQ -w --one-line "command script import ./qq_key_extractor.py"
```

脚本加载后会自动分析 `wrapper.node` 并打印使用说明。

**终端 B**：

```bash
open /Applications/QQ.app
```

回到**终端 A**，按提示操作：

```
# lldb 已 attach，依次输入：
(lldb) process continue          ← 放行，等 QQ 出现登录界面

[等 QQ 出现登录界面，按 Ctrl-C 暂停]

(lldb) qq-setbp                  ← 自动找 slide，自动设断点
# 输出：wrapper.node 加载地址: 0x...  断点已设置

(lldb) c                         ← 继续运行
```

然后在 QQ 界面**点击登录**（或点击任意聊天消息），密钥自动打印：

```
==============================================================
  [+] 密钥提取成功!
  KEY    : <你的密钥会显示在这里>
  LENGTH : 16 bytes
==============================================================
```

QQ 会自动继续运行，无需手动输入 `c`。

---

### 方式 B：手动（仅需 `find_key_func.py`）

先用脚本获取函数 VA：

```bash
python3 find_key_func.py
# 输出示例：
# [+] nt_sqlite3_key_v2 VA: 0x32e74f8
```

然后用 lldb 手动操作：

**终端 A**：

```bash
lldb -n QQ -w
```

**终端 B**：

```bash
open /Applications/QQ.app
```

在**终端 A** 的 lldb 里：

```
(lldb) process continue

[等 QQ 出现登录界面，按 Ctrl-C]

(lldb) image list -o -f | grep wrapper.node
# 示例：[  0] 0x0000000130190000 /Applications/QQ.app/...

(lldb) expr (unsigned long)0x130190000 + 0x32e74f8
# 填入你自己的 slide 和 VA

(lldb) br s -a <上步结果>
(lldb) c
```

在 QQ **点击登录**，断点命中后：

```
(lldb) register read x2 x3
(lldb) memory read --format c --count <x3的值> --size 1 <x2的值>
# 示例输出：<你的密钥>
(lldb) c
```

> **x3 = 密钥实际长度**（通常为 16），以 x3 为准，不要硬编码 16。

---

## 5. 找到数据库文件

**新版 QQ NT（6.9.x）的数据库路径**（注意：不在旧版的 `~/Library/Containers/` 下）：

```bash
ls ~/Library/Application\ Support/QQ/
# 找到 nt_qq_<MD5> 目录

ls ~/Library/Application\ Support/QQ/nt_qq_*/nt_db/
# nt_msg.db  ← 主消息数据库（约 70MB）
# group_info.db
```

备份数据库（**禁止用 sudo cp**，会导致复制出空文件）：

```bash
mkdir -p ~/qq-extract
cp ~/Library/Application\ Support/QQ/nt_qq_*/nt_db/nt_msg.db ~/qq-extract/
```

---

## 6. 解密数据库

参考[基础教程 - NTQQ 解密数据库](基础教程%20-%20NTQQ%20解密数据库.md)，使用以下参数：

```bash
# 去掉 1024 字节文件头
tail -c +1025 ~/qq-extract/nt_msg.db > /tmp/nt_msg.clean.db

# 用 sqlcipher 解密（brew install sqlcipher）
sqlcipher /tmp/nt_msg.clean.db << 'EOF'
PRAGMA key = '<上一步拿到的密钥>';
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 4000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;
.tables
EOF
```

`.tables` 显示表名即解密成功，可看到 `c2c_msg_table`、`group_msg_table` 等。

导出为明文 SQLite：

```bash
sqlcipher /tmp/nt_msg.clean.db << 'EOF'
PRAGMA key = '<密钥>';
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 4000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA1;
PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;
ATTACH DATABASE '/tmp/nt_msg_plain.db' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
EOF
```

---

## 7. 已知问题 & 注意事项

| 问题 | 原因 | 解决 |
|---|---|---|
| `sudo cp` 沙盒数据库 → 复制出空文件 | 沙盒 ACL 保护，root 也无法绕过 | 用普通 `cp`（当前用户有权限） |
| QQ 报"被修改" | ad-hoc 签名替换了原签名 | 忽略，不影响使用 |
| 断点没有命中 | QQ 已自动登录，数据库已打开 | 必须完全关闭 QQ 再重新走 lldb 流程 |
| `image list` 找不到 wrapper.node | 进程太早被暂停，模块未加载 | `process continue` 等几秒再 Ctrl-C |
| `PRAGMA cipher` 报错 | sqlcipher 4.x 已移除该 PRAGMA | 去掉该行，其他参数不变 |
| 密钥长度不是 16 | 版本差异，以 x3 寄存器值为准 | `--count <x3值>` |

---

## 致谢

本教程基于 [lengyue 的原始 ARM 教程](教程%20-%20NTQQ%20(macOS%20ARM).md) 改进，主要贡献：

- **无需关闭 SIP**：用 ad-hoc 重新签名代替禁用 SIP，兼容 macOS 27 Tahoe
- **无需 Hopper**：Python 脚本自动定位函数 VA
- **更新数据库路径**：修正 QQ 6.9.x 的新沙盒路径
- **动态读取密钥长度**：从 x3 寄存器读取实际长度，不硬编码 16 字节
- **测试版本**：QQ NT 6.9.96，macOS 27 Tahoe Developer Beta 1（arm64）
