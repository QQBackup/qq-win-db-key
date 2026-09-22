#!/usr/bin/env python3
"""
find_key_func.py — 从 QQ NT wrapper.node 定位 nt_sqlite3_key_v2 函数入口 VA

用法：
    python3 find_key_func.py [wrapper.node 路径]

不带参数时，分析本机所有可能被 QQ 加载的 wrapper.node：
  - 安装目录：/Applications/QQ.app/Contents/Resources/app/wrapper.node
  - 热更新版本：<数据目录>/versions/<版本>/QQUpdate.app/Contents/Resources/app/wrapper.node
QQ 热更新后，进程仍是 /Applications/QQ.app，但加载的是热更新目录里的 wrapper.node，
各版本的 VA 不同。以 lldb `image list -o -f | grep wrapper.node` 显示的路径为准。
"""

import glob
import json
import struct
import sys
import os

DEFAULT_PATH = "/Applications/QQ.app/Contents/Resources/app/wrapper.node"

# ad-hoc 重签名后 QQ 不在沙盒里，数据目录是前者；官方签名（沙盒）时是后者
DATA_ROOTS = [
    "~/Library/Application Support/QQ",
    "~/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ",
]


def candidate_paths() -> list[tuple[str, str]]:
    """[(wrapper.node 路径, 说明)]：安装目录一份，加上各数据目录下每个热更新版本各一份。"""
    out = []
    if os.path.exists(DEFAULT_PATH):
        out.append((DEFAULT_PATH, "安装目录"))
    for root in DATA_ROOTS:
        root = os.path.expanduser(root)
        try:
            with open(os.path.join(root, "versions", "config.json")) as f:
                cur = json.load(f).get("curVersion", "")
        except (OSError, ValueError):
            cur = ""
        pattern = os.path.join(root, "versions", "*", "*.app", "Contents", "Resources", "app", "wrapper.node")
        for p in sorted(glob.glob(pattern)):
            ver = p[len(os.path.join(root, "versions")) + 1 :].split(os.sep)[0]
            out.append((p, f"热更新 {ver}" + ("（config.json 当前版本）" if ver == cur else "")))
    return out


def find_func_va(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()

    # 安装目录的是 fat binary（x86_64 + arm64），热更新目录的是单架构 arm64 Mach-O
    if struct.unpack(">I", data[:4])[0] == 0xCAFEBABE:
        narch = struct.unpack(">I", data[4:8])[0]
        arm64_offset = None
        for i in range(narch):
            base = 8 + i * 20
            cputype = struct.unpack(">i", data[base : base + 4])[0]
            offset = struct.unpack(">I", data[base + 8 : base + 12])[0]
            if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                arm64_offset = offset
                break

        if arm64_offset is None:
            raise ValueError("未找到 arm64 slice")
    elif struct.unpack("<II", data[:8]) == (0xFEEDFACF, 0x0100000C):  # MH_MAGIC_64 + CPU_TYPE_ARM64
        arm64_offset = 0
    else:
        raise ValueError("不是 arm64 Mach-O，请确认文件是否为 wrapper.node")

    sl = data[arm64_offset:]

    # 解析 Mach-O，找 __text section
    ncmds = struct.unpack("<I", sl[16:20])[0]
    off = 32
    text_vmaddr = text_fileoff = text_size = 0
    for _ in range(ncmds):
        cmd, csz = struct.unpack("<II", sl[off : off + 8])
        if cmd == 0x19:  # LC_SEGMENT_64
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

    # 定位两条诊断字符串（只在 arm64 slice 里找，x86_64 slice 里也有同样的字符串）
    n1 = b"nt_sqlite3_key_v2: db="
    n2 = b"nt_sqlite3_key_v2: no key"
    i1 = data.find(n1, arm64_offset)
    i2 = data.find(n2, arm64_offset)
    if i1 < 0 or i2 < 0:
        raise ValueError("未找到诊断字符串，wrapper.node 版本可能不兼容")

    va1 = i1 - arm64_offset
    va2 = i2 - arm64_offset

    def find_add_imm12(buf: bytes, imm12: int) -> list[int]:
        hits = []
        for i in range(0, len(buf) - 4, 4):
            instr = struct.unpack("<I", buf[i : i + 4])[0]
            # ADD Xn, Xm, #imm12  (encoding: 0x91xxxxxx, bits[21:10] = imm12)
            if (instr & 0xFFC00000) == 0x91000000 and ((instr >> 10) & 0xFFF) == imm12:
                hits.append(i)
        return hits

    h1s = find_add_imm12(text, va1 & 0xFFF)
    h2s = find_add_imm12(text, va2 & 0xFFF)

    # 找包含两条 ADD 的函数，向上回溯到 SUB sp, sp, #imm（函数 prologue）
    for h1 in h1s:
        for h2 in h2s:
            if abs(h1 - h2) < 4096:
                start = min(h1, h2)
                for back in range(0, min(start, 2048), 4):
                    pos = start - back
                    instr = struct.unpack("<I", text[pos : pos + 4])[0]
                    # SUB sp, sp, #imm  (encoding: 0xd1xxxx3ff, bits[4:0]=11111, bits[9:5]=11111)
                    if (instr & 0xFF8003FF) == 0xD10003FF:
                        return text_vmaddr + pos

    raise ValueError("未能定位函数入口，尝试手动分析")


def main():
    if len(sys.argv) > 1:
        paths = [(sys.argv[1], "")]
    else:
        paths = candidate_paths()
        if not paths:
            print(f"[错误] 未找到 wrapper.node: {DEFAULT_PATH}", file=sys.stderr)
            sys.exit(1)

    results = []  # [(路径, VA)]，只收成功的
    for path, note in paths:
        if not os.path.exists(path):
            print(f"[错误] 文件不存在: {path}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] 分析: {path}" + (f"  [{note}]" if note else ""))
        print(f"[*] 文件大小: {os.path.getsize(path) // 1024 // 1024} MB")

        try:
            va = find_func_va(path)
        except ValueError as e:
            print(f"[错误] {e}\n")
            continue

        print(f"[+] nt_sqlite3_key_v2 VA: 0x{va:x}\n")
        results.append((path, va))

    if not results:
        sys.exit(1)

    if len(results) == 1:
        va = results[0][1]
        print("在 lldb 中设置断点（把 <SLIDE> 替换为 image list 拿到的值）：")
        print(f"  (lldb) image list -o -f | grep wrapper.node")
        print(f"  (lldb) expr (unsigned long)0x<SLIDE> + 0x{va:x}")
        print(f"  (lldb) br s -a <上步结果>")
    else:
        print("找到多个 wrapper.node。用 lldb 看 QQ 实际加载的是哪一个，选用对应的 VA：")
        print(f"  (lldb) image list -o -f | grep wrapper.node")
        print(f"  (lldb) expr (unsigned long)0x<SLIDE> + 0x<上面那份对应的 VA>")
        print(f"  (lldb) br s -a <上步结果>")


if __name__ == "__main__":
    main()
