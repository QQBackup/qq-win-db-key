#!/usr/bin/env python3
"""
find_key_func.py — 从 QQ NT wrapper.node 定位 nt_sqlite3_key_v2 函数入口 VA

用法：
    python3 find_key_func.py [wrapper.node 路径]

默认路径：/Applications/QQ.app/Contents/Resources/app/wrapper.node
"""

import struct
import sys
import os

DEFAULT_PATH = "/Applications/QQ.app/Contents/Resources/app/wrapper.node"


def find_func_va(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()

    # fat binary 解析
    if struct.unpack(">I", data[:4])[0] != 0xCAFEBABE:
        raise ValueError("不是 fat binary，请确认文件是否为 wrapper.node")

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

    # 定位两条诊断字符串
    n1 = b"nt_sqlite3_key_v2: db="
    n2 = b"nt_sqlite3_key_v2: no key"
    i1 = data.find(n1)
    i2 = data.find(n2)
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
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH

    if not os.path.exists(path):
        print(f"[错误] 文件不存在: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 分析: {path}")
    print(f"[*] 文件大小: {os.path.getsize(path) // 1024 // 1024} MB")

    va = find_func_va(path)

    print(f"\n[+] nt_sqlite3_key_v2 VA: 0x{va:x}")
    print()
    print("在 lldb 中设置断点（把 <SLIDE> 替换为 image list 拿到的值）：")
    print(f"  (lldb) image list -o -f | grep wrapper.node")
    print(f"  (lldb) expr (unsigned long)0x<SLIDE> + 0x{va:x}")
    print(f"  (lldb) br s -a <上步结果>")


if __name__ == "__main__":
    main()
