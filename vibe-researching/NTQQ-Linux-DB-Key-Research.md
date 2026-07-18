# QQ NT（Linux）数据库密钥机制 — 逆向研究笔记

**完全由 AI 生成，仅供参考！**

分析 js 部分请转： https://github.com/xqy2006/jsc2js
实际调用协议请转： https://napneko.github.io / https://github.com/SnowLuma/SnowLuma
基于此协议的简单易用工具请转： https://github.com/H3CoF6/WeQ

> **状态**：研究进行中，结论基于动态调试与静态分析，偏移量随 QQ 版本变化。  
> **平台**：Linux NTQQ（`wrapper.node`） 3.2.28-48517, Arch Linux, bwrap 容器。
> **目标**：理解 SQLCipher 明文密码从何而来，评估纯离线解密可行性。  
> **配套工具**：[qqnt-dbkey-hook.js](./qqnt-dbkey-hook.js)（Frida 取证脚本，**不含任何真实密钥**）

---

## 声明

本文档仅供学习交流，记录协议与实现层面的观察，**不包含真实账号的 UIN、UID、MachineGUID、key_meta、a2_key 或数据库明文密码**。公开复现时请自行在隔离环境抓取样本，勿将个人密钥写入 issue/PR。

---

## 1. 背景

QQ NT 的聊天数据库使用 SQLCipher 加密。常见做法是在运行时 hook `sqlite3_key_v2` 直接读出密码。本研究尝试**不 hook SQLite**，而是从 DB 文件头、MSF 请求链、session 配置等侧面还原密钥来源。

Linux 版核心逻辑位于 Electron 进程加载的 native 模块：

```
/opt/QQ/resources/app/wrapper.node
```

用户数据大致分布：

| 路径 | 内容 |
|------|------|
| `~/.config/QQ/nt_qq_<实例哈希>/nt_db/` | 加密数据库（`msg_*.db` 等） |
| `~/.config/QQ/nt_qq_<实例哈希>/nt_data/` | 账号级 NT 数据 |
| `~/.config/QQ/global/nt_data/msf/` | 全局 MSF 安全数据 |
| `~/.config/QQ/global/nt_data/mmkv/nt_mmkv_o3` | 加密的 MMKV（设备指纹、QUA 等） |

---

## 2. 两条密钥路径

NTQQ 至少存在两条与数据库相关的密钥逻辑：

### 路径 A：21 个共享 PS 库（主路径）

- 典型文件：`msg_*.db`、`buddy_msg_*.db` 等（约 21 个库共用同一把 key）
- 明文密码：**16 字节 ASCII 字符串**，由账号维度固定（多次登录、多次请求返回相同值）
- **不能**仅从 DB 文件离线推导；需要 MSF 在线服务参与

### 路径 B：`Login.db`

- 走 `DecryptDataOtherOS` 等本地逻辑
- 明文密码形态为 **20 字节 hex 字符串**（与路径 A 不同）
- 与 `MachineGUID` / 设备标识相关，更有希望纯本地还原（Linux 上算法尚未完全对齐）

本笔记主要覆盖**路径 A** 的运行时全链路。

---

## 3. 三个核心概念

### 3.1 `key_meta` — DB 扩展头 field2

每个 NT 数据库文件带有自定义扩展头（protobuf，约 1024 字节），其中 **field2** 存一段 **128 个十六进制字符**（= 64 字节的 ASCII hex 表示）。

QQ 本体称该字段为 **`key_meta`**：它是数据库的**唯一标识**，也是向服务器换取明文 `db_key` 的核心凭证。

示例形态（**虚构，非真实样本**）：

```
a8051982....<共 128 个 hex 字符>....df2ebb
```

特性：

- 写在**磁盘 DB 文件**里，离线可读
- 对**同一账号**通常固定（换登录会话不变）
- **不是** SQLCipher 密码本身，而是发给服务器时的「数据库标识 / 兑换凭证」
- 持有 `key_meta` 即可主动发起解密请求换取当前账号对应库的明文密钥（见 §3.2、§3.3）

### 3.2 `a2_key` — 当次登录会话鉴权 blob（可选）

登录成功后，session 配置里出现 **144 字符 hex**（经 `HexDecode` 变为 **72 字节二进制**），写入 `MSFService+0x210`，并在 OIDB 请求 field7 中**可能**携带。

特性：

- **每次登录变化**（两次登录前缀完全不同）
- 不在 DB 文件明文里；MMKV 磁盘上也为加密存储
- 单独持有无法解密数据库
- **对 `0xcde` SubCommand 2（RequestDecryptKey）而言是可选参数**：只要拥有 `key_meta`，即可在已登录会话中主动触发请求并成功获取当前账号对应数据库的明文密钥；不带鉴权令牌也可正常返回 `db_key`（用其它账号的 `key_meta` 则会报错，如 1006）

猜测：登录早期请求获取密钥时带上 `a2_key`，是因为鉴权流程尚未完成；登录完成后，`a2_key` 便只是可选参数。

来源链（观察到的上游）：

```
登录 ECDH 握手
  → session config 写入（config+0xF0）
  → SessionInit：hex → bytes → MSFService+0x210
  → BuildOidbReq field7（可选携带）
```

`UpdateConfig`（`session_base.cpp`）与 `msf_session_impl` 疑似写入点，但 attach 已登录进程时可能已错过；需**重启 QQ 后尽早 hook**。

### 3.3 MSF / OIDB `0xcde` — 加解密密钥请求

实际用于获取数据库密钥的 OIDB 指令码为 **`0xcde`（decimal 3294）**：

| 指令 | 服务名形态 | 客户端调用 | 时机 | 返回 |
|------|------------|------------|------|------|
| `0xcde` SubCommand **1** | `OidbSvcTrpcTcp.0xcde_1` | `RequestEncryptKey` | 数据库初始化 / 建库 | `key_meta` + `db_key` |
| `0xcde` SubCommand **2** | `OidbSvcTrpcTcp.0xcde_2` | `RequestDecryptKey` | 登录 / 开库解密 | `db_key` |

> **更正**：早期笔记曾将服务名记为 `OidbSvcTrpcTcp.0xce6_2`。`3294 = 0xCDE`，正确指令码为 **`0xcde`**，不是 `0xce6`（0xCE6 = 3302）。

解密请求体（protobuf，约 228 字节量级）典型包含：

- 内层 payload：`key_meta` 的 ASCII 编码
- field7：`72 字节 a2_key` + 时间戳等 varint（**可选**；SnowLuma 实测可不带）

服务器校验通过后，回调 `RequestDecryptKey_cb`，返回：

| 字段 | 典型值 |
|------|--------|
| `meta` | 空字符串 |
| `key` / `db_key` | 16 字节 ASCII（账号固定） |

随后 `SetKeyPair` → SQLCipher 使用该 key 开库。

**离线含义**：仅有 `key_meta`（从 DB 头读取）仍**不能**本地算出 SQLCipher 密码；但在**已登录、能发 OIDB** 的前提下，只需 `key_meta` 即可主动请求换取明文 key，**不必**再依赖当次 `a2_key`。

---

## 4. 运行时调用链（路径 A）

```
MSF OnConnected / 会话就绪
  │
  ├─ requestDBKey (NTWrapperSession)
  │     输入：uid（如 u_xxxxxxxx）、nt_db 目录
  │     扫描各 DB 头 field2 → key_meta
  │
  ├─ RequestDecryptKey (msf_service)
  │     ├─ EncodeReqDecryptKey：key_meta → 内层 protobuf（~134B）
  │     └─ BuildOidbReq (cmd=0xcde / 3294, sub=2)
  │           ├─ payload：内层 protobuf
  │           └─ field7：MSFService+0x210 的 72B a2_key（可选）
  │
  ├─ MSFSign → OidbSvcTrpcTcp.0xcde_2 发包
  │
  └─ RequestDecryptKey_cb
        meta="" , key=<16B ASCII>
        → SetKeyPair → key_mgr → SQLCipher
```

加密方向（建库 / 重写 field2）对称存在 `RequestEncryptKey` / `RequestEncryptKey_cb`（`0xcde` SubCommand 1），删除 DB 触发重建时可观察 `InitDbHeader`；初始化时返回 `key_meta` 与 `db_key`，`key_meta` 写入数据库扩展头。

---

## 5. Session 配置布局（`NTWrapperSessionConfig`）

`session+344` 指向配置块，已确认字段：

| 偏移 | 长度/形态 | 含义 |
|------|-----------|------|
| `+0x58` (88) | 字符串 | `nt_data` 目录路径 |
| `+0xF0` (240) | 144 hex → 72B | `a2_key`，OIDB 鉴权 blob（解密请求可选） |
| `+0x108` (264) | 176 hex → 88B | `sec_material`，≠ DB field2 |
| `+0x120` (288) | hex → ASCII | QUA 等设备标识串 |

初始化链：

```
initComponents
  → sub_242FCE0(session, session+344)
      → SessionInit：config+0xF0 → MSFService+0x210
      → MsfSecuritySignInit：读 nt_mmkv_o3、初始化签名模块
```

### `HexDecode`（`sub_7A02C90`）签名

```
__int64 HexDecode(__int64 out_smallstr, const char *hex_ptr, size_t hex_ascii_len)
```

- 入参是**原始指针 + ASCII 长度**，不是 small-string
- `a2_key` 路径：`hex_ascii_len = 144` → 输出 72 字节

---

## 6. OIDB 请求体结构（BuildOidbReq 输出）

`BuildOidbReq` 输出的 `out_vec` 为完整 OIDB 请求字节流。结构概览（非完整 .proto）：

```
外层 OIDB 头
  field cmd    = 3294 (0xcde)
  field subcmd = 2          // DecryptKey；初始化为 1 (EncryptKey)
  field payload = <EncodeReqDecryptKey 输出>
      内层约 134B，主体为 key_meta 的 ASCII
  field sign_block (tag 0x3a ...)   // 可选
      嵌套 field：72 字节 a2_key 二进制
      + 时间戳 varint 等
```

抓包/日志里可见模式（带鉴权时）：`3a 52 08 08 12 48 <72 bytes> ...`

---

## 7. MMKV 与安全签名

`MsfSecuritySignInit` 使用目录 `.../nt_data/msf`，通过 `SecurityPersistentGet` 读 MMKV 文件 `nt_mmkv_o3`（磁盘加密，搜不到 a2_key 明文）。

已观察到的 MMKV key 名（逻辑名，非值）：

| Key | 内容概要 |
|-----|----------|
| `app_uuid_20240606` | 设备 UUID、MachineGUID（32 hex）、QUA 版本串等 |
| `o3_xwid_switch` | 全局 O3 开关相关 |

`MSFSign` 在登录阶段涉及的模块示例：

- `trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin`
- `trpc.login.ecdh.EcdhService.SsoKeyExchange`
- `trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey`
- `OidbSvcTrpcTcp.0xcde_2`（解密 key 请求签名）

大量 `trpc.o3.report.Report.SsoReport` 为遥测噪音，hook 时应过滤。

---

## 8. Frida 取证脚本

脚本路径：**[qqnt-dbkey-hook.js](./qqnt-dbkey-hook.js)**

设计原则：

- **不 hook** `sqlite3_key_v2`
- 在 `wrapper.node` 镜像偏移处挂钩（需随版本更新 `CFG` 表）
- 解析 QQ NT 自研 `small-string` / `ptr-range` 布局
- 输出 hex dump 供关联分析（运行时会打印**你自己机器上的**敏感数据，请勿公开日志）

### 用法（Linux）

```bash
# 找到 QQ 主进程 PID（示例命令，按实际安装路径调整）
PID=$(pgrep -f '/opt/QQ/electron.*resources/app' | head -1)

# 建议在 QQ 重启后尽快 attach，以抓到 initComponents / SessionInit
timeout 60 frida -p "$PID" -l ./qqnt-dbkey-hook.js
```

触发 `requestDBKey`：通常登录成功、MSF 连接就绪后自动发生；也可尝试开关聊天页促使库打开。

### Hook 点一览（`wrapper.node` 镜像偏移）

| 偏移 | 符号（IDA） | 作用 |
|------|-------------|------|
| `0x4954000` | `InitDbHeader` | field2（`key_meta`）写入（建库） |
| `0x4954350` | `SetExtHeader` | DB 路径 |
| `0x243EFF0` | `RequestDecryptKey_cb` | **明文 key 回调** |
| `0x243E650` | `RequestEncryptKey_cb` | 加密方向（`0xcde` sub=1） |
| `0x2430160` | `requestDBKey` | uid、db 目录 |
| `0x2DDE920` | `RequestDecryptKey` | MSF 发起点（`0xcde` sub=2） |
| `0x2DFA1C0` | `EncodeReqDecryptKey` | `key_meta` 编码 |
| `0x2DDD7F0` | `BuildOidbReq` | 完整 OIDB body |
| `0x2DD6FA0` | `SessionInit` | a2_key → MSFService+0x210 |
| `0x2DD1900` | `MsfSecuritySignInit` | MMKV 初始化 |
| `0x24295A0` | `initComponents` | 更早读 config+0xF0 |
| `0x7A02C90` | `HexDecode` | hex ASCII → bytes |
| `0x48B0FE0` | `UpdateConfig` | 登录写入 config |
| `0x2DD20D0` | `SecurityPersistentGet` | MMKV 读 |
| `0x2DD24A0` | `MSFSign` | 运行时签名 |
| `0x49532C0` | `SetKeyPair` | key 注入 SQLCipher 前 |

> **版本提示**：偏移来自某一版 `wrapper.node`（约 NT 3.2.x Linux）。升级 QQ 后必须用 IDA/Ghidra 重新定位，不可直接套用。

---

## 9. 已确认结论

| 命题 | 结论 |
|------|------|
| 21 个 PS 库的明文 key 存在本地文件吗？ | **否**（需 MSF / OIDB `0xcde` 返回） |
| `key_meta` 能否单独离线算出密码？ | **否**（仍需在线 OIDB） |
| 仅凭 `key_meta` 能否主动请求换 key？ | **能**（登录完成后 `a2_key` 可选） |
| 明文 key 是否随登录变化？ | **否**（同账号多次相同） |
| `a2_key` 是否随登录变化？ | **是** |
| 解密请求是否强制依赖 `a2_key`？ | **否**（可选；登录早期可能带上） |
| Linux field2 走 `EncryptDataOtherOS`/MachineGUID 吗？ | **否**（与 Windows 不同） |
| 已有 DB 会重写 field2 吗？ | 通常**否**（`InitDbHeader` 多在新建库时） |
| `RequestDecryptKey_cb` 的 meta | 通常为空 |
| MMKV 磁盘上有 a2_key 明文吗？ | **未观察到** |

---

## 10. 已排除 / 待验证

**已排除**

- 纯本地从 `key_meta` 反推 SQLCipher 密码（路径 A）
- `sec_material`（config+0x108）等于 DB field2
- 解密请求必须携带 `a2_key`（已由协议复现证伪）

**待继续**

1. `a2_key` 写入链：`UpdateConfig` / `msf_session_impl` 精确调用点
2. MMKV `nt_mmkv_o3` 解密后是否缓存 ECDH 材料
3. ~~用抓到的 `out_vec_raw` 离线复现 OIDB~~ → 已由 SnowLuma 以 `0xcde` sub=2 + 仅 `key_meta` 主动请求验证；可继续对照客户端 `BuildOidbReq` 字段细节
4. 路径 B：`Login.db` + `DecryptDataOtherOS` + MachineGUID 算法对齐
5. 加密方向：删库重建触发 `InitDbHeader`，观察 `key_meta` 生成（`0xcde` sub=1）

---

## 11. 与现有教程的关系

本仓库 [教程 - NTQQ (Linux).md](../教程%20-%20NTQQ%20(Linux).md) 介绍了内存搜索、GDB、第三方 nt-hook 等拿 key 的方法。本文档补充的是**密钥在协议层的来源**，解释为何「只有 DB 文件」往往不够，并为不愿 hook SQLite 的研究者提供另一条取证路径。

若目标仅是**打开自己的库**，运行时 hook 回调拿 16 字节 key 仍是最短路径；若目标是**归档/离线解密**，需面对 MSF/OIDB 依赖或转攻 `Login.db` 本地路径。在已登录会话中，亦可仅凭 DB 头中的 `key_meta` 主动发 `0xcde_2` 换取 key（见 §12 SnowLuma 实现）。

---

## 12. 参考资料

- 本仓库：[基础教程 - NTQQ 解密数据库](../基础教程%20-%20NTQQ%20解密数据库.md)
- 相关项目：[msojocs/nt-hook](https://github.com/msojocs/nt-hook)
- **工程验证**：[SnowLuma PR #69 — Request decrypt database key](https://github.com/SnowLuma/SnowLuma/pull/69)（仅依赖 `key_meta` 主动请求 `0xcde` sub=2）
  - 实现：[packages/protocol/src/oidb-services/misc/request-decrypt-key.ts](https://github.com/SnowLuma/SnowLuma/blob/main/packages/protocol/src/oidb-services/misc/request-decrypt-key.ts)
- 工具：Frida、IDA Pro / Ghidra

---

*文档版本：2026-07-18 · 研究笔记，随 QQ 更新可能失效*
