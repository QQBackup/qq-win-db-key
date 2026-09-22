"""
qq_key_extractor.py — lldb 自动化模块，一键提取 QQ NT 数据库密钥

用法（两个终端）：

  终端 A：
    lldb -n QQ -w --one-line "command script import /path/to/qq_key_extractor.py"

  终端 B（等 lldb 显示 Waiting for process 'QQ' 后）：
    open /Applications/QQ.app

  回到终端 A，lldb 已 attach，依次输入：
    (lldb) process continue          ← 放行，等 QQ 出现登录界面
    Ctrl-C                           ← 暂停
    (lldb) qq-setbp                  ← 自动找 slide，设断点
    (lldb) c                         ← 继续
    [在 QQ 点击登录]
    → 密钥自动打印，QQ 正常运行

QQ 热更新后，加载的是数据目录 versions/<版本>/ 下的 wrapper.node，各版本 VA 不同；
qq-setbp 按实际加载的 wrapper.node 计算 VA。

依赖：仅 Python 标准库 + lldb（Xcode CLT 自带）
测试：QQ NT 6.9.96，macOS 27 Tahoe，Apple Silicon
      QQ NT 6.9.96 热更新至 7.0.2-53489，macOS 26.5，Apple Silicon
"""

# Xcode 自带 lldb 的 Python 是 3.9，不支持运行时求值 `int | None` 这类注解
from __future__ import annotations

import lldb
import os
import struct

_va_cache: dict[str, tuple[int | None, str | None]] = {}  # wrapper.node 路径 → (VA, 错误信息)

WRAPPER_PATH = "/Applications/QQ.app/Contents/Resources/app/wrapper.node"

# login.db 的固定 key，所有账号、所有设备都相同，不是聊天记录的 key。
# QQ 启动时（登录前）打开 login.db 也会经过 nt_sqlite3_key_v2，命中时跳过。
LOGIN_DB_KEY = "BD156D6710D54D8782F4"


# ── 二进制分析 ─────────────────────────────────────────────────────────────────

def _find_func_va(path: str) -> tuple[int | None, str | None]:
    with open(path, "rb") as f:
        data = f.read()

    # 安装目录的是 fat binary（x86_64 + arm64），热更新目录的是单架构 arm64 Mach-O
    if struct.unpack(">I", data[:4])[0] == 0xCAFEBABE:
        narch = struct.unpack(">I", data[4:8])[0]
        arm64_off = None
        for i in range(narch):
            base = 8 + i * 20
            cputype = struct.unpack(">i", data[base : base + 4])[0]
            offset = struct.unpack(">I", data[base + 8 : base + 12])[0]
            if cputype == 0x0100000C:
                arm64_off = offset
                break

        if arm64_off is None:
            return None, "no arm64 slice"
    elif struct.unpack("<II", data[:8]) == (0xFEEDFACF, 0x0100000C):
        arm64_off = 0
    else:
        return None, "not an arm64 Mach-O"

    sl = data[arm64_off:]
    ncmds = struct.unpack("<I", sl[16:20])[0]
    off = 32
    text_vmaddr = text_fileoff = text_size = 0

    for _ in range(ncmds):
        cmd, csz = struct.unpack("<II", sl[off : off + 8])
        if cmd == 0x19:
            nsects = struct.unpack("<I", sl[off + 64 : off + 68])[0]
            s = off + 72
            for _ in range(nsects):
                sname = sl[s : s + 16].rstrip(b"\x00").decode("ascii", errors="replace")
                sgname = sl[s + 16 : s + 32].rstrip(b"\x00").decode("ascii", errors="replace")
                saddr, ssz = struct.unpack("<QQ", sl[s + 32 : s + 48])
                sfoff = struct.unpack("<I", sl[s + 48 : s + 52])[0]
                if sname == "__text" and sgname == "__TEXT":
                    text_vmaddr, text_fileoff, text_size = saddr, sfoff, ssz
                s += 80
        off += csz

    text = sl[text_fileoff : text_fileoff + text_size]

    # 只在 arm64 slice 里找，x86_64 slice 里也有同样的字符串
    n1 = b"nt_sqlite3_key_v2: db="
    n2 = b"nt_sqlite3_key_v2: no key"
    i1 = data.find(n1, arm64_off)
    i2 = data.find(n2, arm64_off)
    if i1 < 0 or i2 < 0:
        return None, "diagnostic strings not found — incompatible wrapper.node?"

    va1 = i1 - arm64_off
    va2 = i2 - arm64_off

    def find_add(buf: bytes, imm12: int) -> list:
        return [
            i for i in range(0, len(buf) - 4, 4)
            if (struct.unpack("<I", buf[i : i + 4])[0] & 0xFFC00000) == 0x91000000
            and (struct.unpack("<I", buf[i : i + 4])[0] >> 10 & 0xFFF) == imm12
        ]

    for h1 in find_add(text, va1 & 0xFFF):
        for h2 in find_add(text, va2 & 0xFFF):
            if abs(h1 - h2) < 4096:
                start = min(h1, h2)
                for back in range(0, min(start, 2048), 4):
                    pos = start - back
                    if (struct.unpack("<I", text[pos : pos + 4])[0] & 0xFF8003FF) == 0xD10003FF:
                        return text_vmaddr + pos, None

    return None, "function entry not found"


def _va_for(path: str) -> tuple[int | None, str | None]:
    """按路径缓存分析结果，同一个 wrapper.node 只分析一次。"""
    if path not in _va_cache:
        _va_cache[path] = _find_func_va(path)
    return _va_cache[path]


# ── lldb 断点回调 ──────────────────────────────────────────────────────────────

def _key_callback(frame, bp_loc, extra_args, internal_dict):
    """断点命中时自动读取 x2/x3，打印密钥，然后让 QQ 继续运行。"""
    process = frame.GetThread().GetProcess()

    x2 = frame.FindRegister("x2")
    x3 = frame.FindRegister("x3")
    if not x2.IsValid() or not x3.IsValid():
        print("[qq-key] ERROR: cannot read x2/x3 registers")
        return False

    ptr = x2.GetValueAsUnsigned()
    length = x3.GetValueAsUnsigned()

    err = lldb.SBError()
    raw = process.ReadMemory(ptr, length, err)

    sep = "=" * 62
    if err.Success():
        try:
            key = raw.decode("ascii")
        except Exception:
            key = raw.hex()

        if key == LOGIN_DB_KEY:
            print("[qq-key] 命中 login.db 的固定 key（不是聊天记录的 key），跳过，继续等待...")
            process.Continue()
            return False

        print(f"\n{sep}")
        print(f"  [+] 密钥提取成功!")
        print(f"  KEY    : {key}")
        print(f"  LENGTH : {length} bytes")
        print(f"{sep}")
        print()
        print("  数据库路径：")
        print("    ~/Library/Application Support/QQ/nt_qq_<hash>/nt_db/nt_msg.db")
        print()
        print("  解密步骤：")
        print("    tail -c +1025 nt_msg.db > nt_msg.clean.db")
        print(f"    sqlcipher nt_msg.clean.db << 'EOF'")
        print(f"    PRAGMA key = '{key}';")
        print(f"    PRAGMA cipher_page_size = 4096;")
        print(f"    PRAGMA kdf_iter = 4000;")
        print(f"    PRAGMA cipher_hmac_algorithm = HMAC_SHA1;")
        print(f"    PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;")
        print(f"    .tables")
        print(f"    EOF")
        print()
    else:
        print(f"[qq-key] ERROR reading memory: {err}")

    process.Continue()
    return False


# ── qq-setbp 命令 ──────────────────────────────────────────────────────────────

def set_breakpoint(debugger, command, result, internal_dict):
    """
    qq-setbp：在当前已加载的 wrapper.node 上自动计算断点地址并设置。
    在 QQ 出现登录界面后，Ctrl-C 暂停，执行此命令。
    VA 按实际加载的 wrapper.node 计算（热更新后它不在 /Applications 里）。
    """
    target = debugger.GetSelectedTarget()
    for i in range(target.GetNumModules()):
        mod = target.GetModuleAtIndex(i)
        if mod.GetFileSpec().GetFilename() != "wrapper.node":
            continue

        load_addr = mod.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if load_addr == lldb.LLDB_INVALID_ADDRESS:
            continue

        path = mod.GetFileSpec().fullpath
        va, err = _va_for(path)
        if va is None:
            result.SetError(f"[qq-key] 未能在 {path} 中定位函数: {err}")
            return

        bp_addr = load_addr + va
        print(f"[qq-key] wrapper.node 路径     : {path}")
        print(f"[qq-key] nt_sqlite3_key_v2 VA  : 0x{va:x}")
        print(f"[qq-key] wrapper.node 加载地址 : 0x{load_addr:x}")
        print(f"[qq-key] nt_sqlite3_key_v2     : 0x{bp_addr:x}")

        bp = target.BreakpointCreateByAddress(bp_addr)
        if not bp.IsValid():
            result.SetError(f"[qq-key] 创建断点失败（地址 0x{bp_addr:x}）")
            return

        bp.SetScriptCallbackFunction("qq_key_extractor._key_callback")
        print(f"[qq-key] 断点已设置 (id={bp.GetID()})")
        print("[qq-key] 输入 c 继续，然后在 QQ 点击登录，密钥将自动打印")
        return

    result.SetError(
        "[qq-key] 未找到 wrapper.node 模块 — QQ 是否已加载？\n"
        "         请先 'process continue'，等登录界面出现后 Ctrl-C，再执行 qq-setbp"
    )


# ── 模块入口 ───────────────────────────────────────────────────────────────────

def __lldb_init_module(debugger, internal_dict):
    print(f"\n[qq-key] 分析 wrapper.node ...")

    # 预先分析安装目录那份；QQ 热更新过的话，qq-setbp 时会按实际加载的文件重新计算
    if os.path.exists(WRAPPER_PATH):
        va, err = _va_for(WRAPPER_PATH)
        if va is None:
            print(f"[qq-key] 安装目录的 wrapper.node 未能定位函数: {err}")
        else:
            print(f"[qq-key] nt_sqlite3_key_v2 VA : 0x{va:x}（安装目录；热更新后以实际加载的为准）")
    else:
        print(f"[qq-key] 未找到 {WRAPPER_PATH}，qq-setbp 时按实际加载的 wrapper.node 计算")

    debugger.HandleCommand("command script add -f qq_key_extractor.set_breakpoint qq-setbp")

    print()
    print("[qq-key] ── 使用步骤 ──────────────────────────────────────────")
    print("[qq-key]  1. 在另一个终端运行: open /Applications/QQ.app")
    print("[qq-key]  2. 回到这里: process continue")
    print("[qq-key]  3. 等 QQ 出现登录界面，按 Ctrl-C 暂停")
    print("[qq-key]  4. 输入: qq-setbp")
    print("[qq-key]  5. 输入: c")
    print("[qq-key]  6. 在 QQ 点击登录 → 密钥自动打印，QQ 正常运行")
    print("[qq-key] ─────────────────────────────────────────────────────")
    print()
