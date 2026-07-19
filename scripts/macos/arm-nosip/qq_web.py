#!/usr/bin/env python3
"""
QQ NT 数据库提取工具 — Web UI
依赖: pip install flask  |  brew install sqlcipher

运行: python3 qq_web.py   (自动打开浏览器)
"""

from flask import Flask, jsonify, request
import threading, subprocess, os, glob, json, re, time, struct, sqlite3, webbrowser
import shutil, datetime
from pathlib import Path

app = Flask(__name__)
WRAPPER = "/Applications/QQ.app/Contents/Resources/app/wrapper.node"

# qq_key_extractor.py 内嵌内容，运行时写到临时文件，用完自动清理
_EXTRACTOR_SRC = r'''
import lldb, os, struct, threading, time

_func_va = None
WRAPPER = "/Applications/QQ.app/Contents/Resources/app/wrapper.node"

def _find_func_va(path):
    with open(path, "rb") as f: data = f.read()
    if struct.unpack(">I", data[:4])[0] != 0xCAFEBABE: return None
    narch = struct.unpack(">I", data[4:8])[0]
    arm64 = None
    for i in range(narch):
        base = 8 + i * 20
        if struct.unpack(">i", data[base:base+4])[0] == 0x0100000C:
            arm64 = struct.unpack(">I", data[base+8:base+12])[0]; break
    if arm64 is None: return None
    sl = data[arm64:]; off = 32; tv = tf = ts = 0
    for _ in range(struct.unpack("<I", sl[16:20])[0]):
        cmd, csz = struct.unpack("<II", sl[off:off+8])
        if cmd == 0x19:
            s = off + 72
            for _ in range(struct.unpack("<I", sl[off+64:off+68])[0]):
                sn = sl[s:s+16].rstrip(b"\x00").decode("ascii","replace")
                sg = sl[s+16:s+32].rstrip(b"\x00").decode("ascii","replace")
                if sn == "__text" and sg == "__TEXT":
                    tv = struct.unpack("<Q", sl[s+32:s+40])[0]
                    ts = struct.unpack("<Q", sl[s+40:s+48])[0]
                    tf = struct.unpack("<I", sl[s+48:s+52])[0]
                s += 80
        off += csz
    txt = sl[tf:tf+ts]
    i1 = data.find(b"nt_sqlite3_key_v2: db=", arm64)
    i2 = data.find(b"nt_sqlite3_key_v2: no key", arm64)
    if i1 < 0 or i2 < 0: return None
    va1, va2 = i1-arm64, i2-arm64
    def adc(buf, imm):
        return [i for i in range(0,len(buf)-4,4)
                if struct.unpack("<I",buf[i:i+4])[0]&0xFFC00000==0x91000000
                and struct.unpack("<I",buf[i:i+4])[0]>>10&0xFFF==imm]
    for h1 in adc(txt, va1&0xFFF):
        for h2 in adc(txt, va2&0xFFF):
            if abs(h1-h2)<4096:
                for back in range(0, min(min(h1,h2),2048), 4):
                    pos = min(h1,h2)-back
                    if struct.unpack("<I",txt[pos:pos+4])[0]&0xFF8003FF==0xD10003FF:
                        return tv+pos
    return None

def _key_callback(frame, bp_loc, extra_args, internal_dict):
    process = frame.GetThread().GetProcess()
    x2 = frame.FindRegister("x2"); x3 = frame.FindRegister("x3")
    if not x2.IsValid() or not x3.IsValid(): return False
    err = lldb.SBError()
    raw = process.ReadMemory(x2.GetValueAsUnsigned(), x3.GetValueAsUnsigned(), err)
    if err.Success():
        try: key = raw.decode("ascii")
        except: key = raw.hex()
        with open("/tmp/qq_key_result.txt", "w") as f: f.write(key)
        print(f"\nKEY    : {key}", flush=True)
        print(f"LENGTH : {x3.GetValueAsUnsigned()}", flush=True)
    return False  # don't stop; process continues automatically

def set_breakpoint(debugger, command, result, internal_dict):
    """qq-setbp: set bp on nt_sqlite3_key_v2 in already-loaded wrapper.node"""
    global _func_va
    if _func_va is None: result.SetError("VA not computed"); return
    target = debugger.GetSelectedTarget()
    for i in range(target.GetNumModules()):
        mod = target.GetModuleAtIndex(i)
        if mod.GetFileSpec().GetFilename() != "wrapper.node": continue
        load_addr = mod.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if load_addr == lldb.LLDB_INVALID_ADDRESS: continue
        bp_addr = load_addr + _func_va
        bp = target.BreakpointCreateByAddress(bp_addr)
        bp.SetScriptCallbackFunction("qq_key_extractor._key_callback")
        with open("/tmp/qq_bp_set.txt", "w") as f: f.write(f"0x{bp_addr:x}")
        print(f"\n[qq-key] OK 断点已设置 bp=0x{bp_addr:x} (id={bp.GetID()})", flush=True)
        return
    result.SetError("wrapper.node not in module list")

def __lldb_init_module(debugger, internal_dict):
    global _func_va
    print("\n[qq-key] 分析 wrapper.node ...", flush=True)
    va = _find_func_va(WRAPPER)
    if va is None: print("[qq-key] ERROR: 未能定位函数", flush=True); return
    _func_va = va
    print(f"[qq-key] VA=0x{va:x}", flush=True)
    debugger.HandleCommand("command script add -f qq_key_extractor.set_breakpoint qq-setbp")
    with open("/tmp/qq_script_ready.txt", "w") as f: f.write(f"0x{va:x}")
    print("[qq-key] 就绪", flush=True)
'''

def _extractor_path():
    """将内嵌的 extractor 脚本写到 /tmp，返回路径。"""
    p = "/tmp/qq_key_extractor.py"
    with open(p, "w") as f:
        f.write(_EXTRACTOR_SRC.lstrip())
    return p

SCRIPT = _extractor_path()

# ── 全局状态（单用户本地工具，不需要并发安全）────────────────────────────────
def _is_adhoc():
    r = subprocess.run(["codesign", "-dv", "/Applications/QQ.app"],
                       capture_output=True, text=True)
    return "adhoc" in (r.stdout + r.stderr).lower()

# 启动时立即探测：若已 ad-hoc 签名则初始化为 signed
_init_phase = "signed" if _is_adhoc() else "idle"
S = {"phase": _init_phase, "log": [], "key": ""}
EX = {"running": False, "progress": 0.0, "status": "", "error": ""}
_lldb = None
_qq_pid = None   # PID of main QQ process (Contents/MacOS/QQ)

# ── 二进制分析 ─────────────────────────────────────────────────────────────────

def _find_va(path):
    with open(path, "rb") as f: data = f.read()
    if struct.unpack(">I", data[:4])[0] != 0xCAFEBABE: raise ValueError("not fat binary")
    narch = struct.unpack(">I", data[4:8])[0]
    arm64 = next((struct.unpack(">I", data[8+i*20+8:8+i*20+12])[0]
                  for i in range(narch)
                  if struct.unpack(">i", data[8+i*20:8+i*20+4])[0] == 0x0100000C), None)
    if arm64 is None: raise ValueError("no arm64 slice")
    sl = data[arm64:]
    off = 32; tv = tf = ts = 0
    for _ in range(struct.unpack("<I", sl[16:20])[0]):
        cmd, csz = struct.unpack("<II", sl[off:off+8])
        if cmd == 0x19:
            s = off + 72
            for _ in range(struct.unpack("<I", sl[off+64:off+68])[0]):
                sn = sl[s:s+16].rstrip(b"\x00").decode("ascii","replace")
                sg = sl[s+16:s+32].rstrip(b"\x00").decode("ascii","replace")
                if sn == "__text" and sg == "__TEXT":
                    tv = struct.unpack("<Q", sl[s+32:s+40])[0]
                    ts = struct.unpack("<Q", sl[s+40:s+48])[0]
                    tf = struct.unpack("<I", sl[s+48:s+52])[0]
                s += 80
        off += csz
    txt = sl[tf:tf+ts]
    i1 = data.find(b"nt_sqlite3_key_v2: db=", arm64)
    i2 = data.find(b"nt_sqlite3_key_v2: no key", arm64)
    if i1 < 0 or i2 < 0: raise ValueError("diagnostic strings not found")
    va1, va2 = i1-arm64, i2-arm64
    def adc(buf, imm):
        return [i for i in range(0,len(buf)-4,4)
                if struct.unpack("<I",buf[i:i+4])[0]&0xFFC00000==0x91000000
                and struct.unpack("<I",buf[i:i+4])[0]>>10&0xFFF==imm]
    for h1 in adc(txt, va1&0xFFF):
        for h2 in adc(txt, va2&0xFFF):
            if abs(h1-h2)<4096:
                for back in range(0,min(min(h1,h2),2048),4):
                    pos=min(h1,h2)-back
                    if struct.unpack("<I",txt[pos:pos+4])[0]&0xFF8003FF==0xD10003FF:
                        return tv+pos
    raise ValueError("function entry not found")

# ── Protobuf ───────────────────────────────────────────────────────────────────

def _vi(d, p):
    r=s=0
    while True:
        b=d[p]; p+=1; r|=(b&127)<<s
        if not b&128: break
        s+=7
    return r,p

def _parse(blob):
    texts, marker = [], None
    try:
        p=0
        while p<len(blob):
            tag,p=_vi(blob,p); w=tag&7
            if w==0: _,p=_vi(blob,p)
            elif w==2:
                l,p=_vi(blob,p); inn=blob[p:p+l]; p+=l; ip=0
                while ip<len(inn):
                    it,ip=_vi(inn,ip); f,iw=it>>3,it&7
                    if iw==0: _,ip=_vi(inn,ip)
                    elif iw==2:
                        il,ip=_vi(inn,ip); d2=inn[ip:ip+il]; ip+=il
                        if f==45101:
                            try: texts.append(d2.decode("utf-8"))
                            except: pass
                        elif f==49154:
                            try: marker=d2.decode("utf-8")
                            except: pass
                    else: break
            else: break
    except: pass
    return "\n".join(texts), marker

# ── 解密 & 导出 ────────────────────────────────────────────────────────────────

def _decrypt(db, key):
    clean, plain = "/tmp/_qqc.db", "/tmp/_qqp.db"
    for p in (clean, plain):
        if os.path.exists(p): os.unlink(p)
    with open(db,"rb") as f: raw=f.read()
    with open(clean,"wb") as f: f.write(raw[1024:])
    sql=(f"PRAGMA key='{key}';\nPRAGMA cipher_page_size=4096;\n"
         "PRAGMA kdf_iter=4000;\nPRAGMA cipher_hmac_algorithm=HMAC_SHA1;\n"
         "PRAGMA cipher_default_kdf_algorithm=PBKDF2_HMAC_SHA512;\n"
         f"ATTACH DATABASE '{plain}' AS pt KEY '';\n"
         "SELECT sqlcipher_export('pt');\nDETACH DATABASE pt;\n")
    r=subprocess.run(["sqlcipher",clean],input=sql,capture_output=True,text=True)
    if not os.path.exists(plain) or os.path.getsize(plain)<4096:
        raise RuntimeError(f"解密失败（密钥错误？）\n{r.stderr.strip()}")
    return plain

def _msgs(plain, marker="nt_2", pcb=None):
    con=sqlite3.connect(plain)
    tbls=[r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%msg_table%'")]
    out=[]
    for i,t in enumerate(tbls):
        try:
            for ts,blob in con.execute(f"SELECT msgTime,msgData FROM {t} ORDER BY msgTime"):
                if not blob: continue
                text,mk=_parse(blob)
                if text.strip():
                    out.append({"ts":ts,"me":mk==marker if mk else False,"text":text})
        except: pass
        if pcb: pcb((i+1)/max(len(tbls),1))
    con.close()
    out.sort(key=lambda x:x["ts"])
    return out

def _html(msgs):
    import html as h, datetime
    rows=["<!DOCTYPE html><html><head><meta charset='utf-8'><title>QQ 聊天记录</title><style>"
          "body{font-family:-apple-system,sans-serif;background:#ECE5DD;margin:0;padding:16px}"
          ".day{text-align:center;color:#888;font-size:12px;margin:16px 0 8px}"
          ".row{display:flex;margin:3px 0;align-items:flex-end;gap:8px}"
          ".row.me{flex-direction:row-reverse}"
          ".b{max-width:65%;padding:9px 13px;border-radius:18px;font-size:14px;"
          "   line-height:1.55;word-break:break-word;white-space:pre-wrap}"
          ".row:not(.me) .b{background:#fff;border-bottom-left-radius:3px}"
          ".row.me .b{background:#95EC69;border-bottom-right-radius:3px}"
          ".ts{font-size:11px;color:#aaa;white-space:nowrap}"
          "</style></head><body>"]
    last=None
    for m in msgs:
        dt=datetime.datetime.fromtimestamp(m["ts"])
        d=dt.strftime("%Y年%m月%d日")
        if d!=last: rows.append(f'<div class="day">{d}</div>'); last=d
        me=" me" if m.get("me") else ""
        rows.append(f'<div class="row{me}"><span class="ts">{dt.strftime("%H:%M")}</span>'
                    f'<div class="b">{h.escape(m["text"])}</div></div>')
    rows.append("</body></html>")
    return "".join(rows)

# ── lldb 管理 ──────────────────────────────────────────────────────────────────

def _log(line): S["log"].append(line.rstrip())

def _lldb_send(cmd):
    global _lldb
    if _lldb and _lldb.poll() is None:
        _lldb.stdin.write(cmd+"\n"); _lldb.stdin.flush()

def _on_attached():
    """Called when QQ process stops at attach. Immediately continue — polling thread handles BP."""
    if S["phase"] != "launching":
        return
    S["phase"] = "running"
    _log("[*] QQ 已附加，继续运行，等待 wrapper.node 加载...")
    time.sleep(0.3)
    _lldb_send("process continue")

def _poll_key_file():
    """Poll /tmp/qq_key_result.txt as backup for buffered stdout KEY detection."""
    for _ in range(1200):  # 10 min
        time.sleep(0.5)
        if S["phase"] in ("done", "idle", "signed"):
            return
        try:
            with open("/tmp/qq_key_result.txt") as f:
                key = f.read().strip()
            if key:
                S["key"] = key
                S["phase"] = "done"
                _log(f"[+] 密钥已获取（文件信号）：{key}")
                return
        except FileNotFoundError:
            pass

def _launch_watchdog():
    """Log a hint if phase stays 'launching' for >120s."""
    time.sleep(120)
    if S["phase"] == "launching":
        _log("[~] attach 进行中（Electron 进程需要较长时间），请继续等待...")

def _monitor_wrapper():
    """Wait for QQ PID, then for attach to complete, then detect wrapper.node and set BP."""
    # Phase 0: wait for _qq_pid to be set (max 30s)
    for _ in range(60):
        time.sleep(0.5)
        if S["phase"] in ("waiting", "done", "signed", "idle"):
            return
        if _qq_pid:
            break
    else:
        _log("[!] 超时：未找到 QQ 主进程")
        return

    # Phase 1: wait for phase→"running" (stdout-triggered by _on_attached).
    # Fallback: Electron attach takes ~60-90s; after 110s force "running".
    pid_found_t = time.time()
    for i in range(360):  # up to 3 min
        time.sleep(0.5)
        ph = S["phase"]
        if ph in ("waiting", "done", "signed", "idle"):
            return
        if ph == "running":
            break
        elapsed = int(time.time() - pid_found_t)
        if elapsed > 110:
            _log("[*] attach 耗时较长，直接推进（QQ 进程较复杂属正常）...")
            S["phase"] = "running"
            break
        if elapsed > 0 and elapsed % 20 == 0 and i % 2 == 0:
            _log(f"[~] 正在等待 lldb attach 完成（已等 {elapsed}s，Electron 进程通常需要 60-90s）...")
    else:
        _log("[!] 超时：未能完成 attach")
        return

    # Phase 2: lsof-poll for wrapper.node (up to 120s)
    for _ in range(240):
        time.sleep(0.5)
        ph = S["phase"]
        if ph in ("waiting", "done", "signed", "idle"):
            return
        r = subprocess.run(
            ["lsof", f"-p{_qq_pid}", "-n", "-w"],
            capture_output=True, text=True, timeout=5
        )
        if "wrapper.node" in r.stdout:
            _log(f"[*] wrapper.node 已加载 (PID={_qq_pid})，正在中断并设置断点...")
            _lldb_send("process interrupt")
            time.sleep(1.5)
            _lldb_send("qq-setbp")
            # Poll /tmp/qq_bp_set.txt — bypasses stdout buffering
            for _ in range(60):  # 30s
                time.sleep(0.5)
                if os.path.exists("/tmp/qq_bp_set.txt"):
                    _log("[*] 断点已就绪！")
                    _log("[*] → 若 QQ 显示登录界面：直接点击「登录」按钮")
                    _log("[*] → 若 QQ 已自动登录（显示聊天列表）：在 QQ 菜单中选择「退出账号」，返回登录界面后再点登录")
                    _log("[*]   （不要关闭 QQ，直接在 QQ 里操作即可）")
                    S["phase"] = "waiting"
                    threading.Thread(target=_poll_key_file, daemon=True).start()
                    break
            _lldb_send("process continue")
            return
    _log("[!] wrapper.node 未在 120s 内加载")

def _read_lldb():
    global _lldb
    for line in _lldb.stdout:
        _log(line.rstrip())
        # Detect process attach ("Process X stopped" or "Process X launched:")
        if S["phase"] == "launching" and "Process" in line and (
                "stopped" in line or "launched:" in line):
            _on_attached()
        # qq-setbp set the breakpoint (via _monitor_wrapper interrupt)
        if "[qq-key] OK 断点已设置" in line and S["phase"] == "running":
            S["phase"] = "waiting"
            _log("[*] 断点已就绪！")
            _log("[*] → 若 QQ 显示登录界面：直接点击「登录」按钮")
            _log("[*] → 若 QQ 已自动登录（显示聊天列表）：在 QQ 菜单中选择「退出账号」，返回登录界面后再点登录")
            _log("[*]   （不要关闭 QQ，直接在 QQ 里操作即可）")
        if "KEY    :" in line:
            m = re.search(r"KEY\s+:\s+(.+)", line)
            if m: S["key"] = m.group(1).strip(); S["phase"] = "done"

# ── API ────────────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return HTML

@app.route("/api/status")
def status():
    since=request.args.get("since",0,type=int)
    return jsonify({"phase":S["phase"],"key":S["key"],
                    "log":S["log"][since:],"total":len(S["log"])})

def _backup_db():
    """备份 nt_msg.db，返回备份路径或 None。"""
    hits = glob.glob(os.path.expanduser(
        "~/Library/Application Support/QQ/nt_qq_*/nt_db/nt_msg.db"))
    if not hits:
        return None
    backup_dir = Path.home() / "qq-extract-backup"
    backup_dir.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = backup_dir / f"nt_msg_{ts}.db"
    shutil.copy2(hits[0], dest)
    return str(dest)

@app.route("/api/check-sign")
def check_sign():
    adhoc = _is_adhoc()
    return jsonify({"adhoc": adhoc})

@app.route("/api/sign", methods=["POST"])
def sign():
    # 已是 ad-hoc 签名，直接跳过
    if S["phase"] == "signed":
        _log("[+] QQ 已是 ad-hoc 签名，无需重新签名")
        return jsonify({"ok": True, "skipped": True})

    S["phase"] = "signing"
    _log("[*] 正在备份数据库（签名前必须备份）...")

    def _do():
        # 先备份
        backup = _backup_db()
        if backup:
            _log(f"[+] 数据库已备份至: {backup}")
        else:
            _log("[~] 未检测到数据库文件，跳过备份")

        _log("[*] 正在对 QQ 重新签名（会弹出系统密码框）...")
        r = subprocess.run(["osascript", "-e",
            'do shell script "codesign --remove-signature /Applications/QQ.app 2>/dev/null; '
            'codesign --force --deep --sign - /Applications/QQ.app" '
            'with administrator privileges'], capture_output=True, text=True)
        if r.returncode != 0:
            _log(f"[!] 签名失败: {r.stderr.strip()}")
            S["phase"] = "idle"
        else:
            _log("[+] 签名完成")
            S["phase"] = "signed"

    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/launch",methods=["POST"])
def launch():
    global _lldb
    script = _extractor_path()
    try:
        va=_find_va(WRAPPER)
        _log(f"[+] nt_sqlite3_key_v2 VA: 0x{va:x}")
    except Exception as e:
        return jsonify({"ok":False,"err":str(e)})
    # Clean up stale file signals from a previous run
    for f in ("/tmp/qq_script_ready.txt", "/tmp/qq_bp_set.txt", "/tmp/qq_key_result.txt"):
        try: os.remove(f)
        except FileNotFoundError: pass
    global _qq_pid
    _qq_pid = None
    S["phase"]="launching"
    S["key"]=""
    # Kill ALL QQ processes (main + helpers) to ensure a clean start
    subprocess.run(["pkill","-9","-f","QQ.app"],capture_output=True)
    time.sleep(1)
    # Start lldb with only the script import — we will attach by PID once QQ starts
    _lldb=subprocess.Popen(
        ["lldb","--one-line",f"command script import {script}"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        text=True,bufsize=1)
    threading.Thread(target=_read_lldb,daemon=True).start()
    threading.Thread(target=_launch_watchdog,daemon=True).start()

    def _start_and_attach():
        global _qq_pid
        subprocess.Popen(["open","/Applications/QQ.app"])
        _log("[*] QQ 启动中，正在寻找主进程（Contents/MacOS/QQ）...")
        for _ in range(40):        # 20s timeout finding the PID
            time.sleep(0.5)
            r = subprocess.run(["pgrep","-f","QQ.app/Contents/MacOS/QQ"],
                               capture_output=True,text=True)
            pids = [p.strip() for p in r.stdout.strip().split('\n') if p.strip()]
            if pids:
                pid = pids[0]
                _qq_pid = pid
                _log(f"[*] 找到主进程 PID={pid}，正在 attach...")
                _lldb_send(f"process attach --pid {pid}")
                return
        _log("[!] 未找到 QQ 主进程，请手动重试")
        S["phase"] = "signed"

    threading.Thread(target=_start_and_attach,daemon=True).start()
    threading.Thread(target=_monitor_wrapper,daemon=True).start()
    return jsonify({"ok":True})

@app.route("/api/trigger",methods=["POST"])
def trigger():
    if S["phase"]!="running":
        return jsonify({"ok":False,"err":"请先等 QQ 启动后再点击"})
    S["phase"]="interrupting"
    _log("[*] 暂停 QQ，设置断点...")
    def _do():
        _lldb_send("process interrupt"); time.sleep(1.2)
        _lldb_send("qq-setbp"); time.sleep(0.4)
        _lldb_send("c"); S["phase"]="waiting"
        _log("[*] 请在 QQ 点击登录，或随便点开一个聊天窗口...")
    threading.Thread(target=_do,daemon=True).start()
    return jsonify({"ok":True})

@app.route("/api/export",methods=["POST"])
def do_export():
    d=request.json or {}
    db=d.get("db",""); key=d.get("key",""); out=d.get("out",""); fmt=d.get("fmt","html")
    marker=d.get("marker","nt_2")
    if not key: return jsonify({"ok":False,"err":"请先获取密钥"})
    if not os.path.exists(db): return jsonify({"ok":False,"err":f"数据库不存在: {db}"})
    if subprocess.run(["which","sqlcipher"],capture_output=True).returncode!=0:
        return jsonify({"ok":False,"err":"sqlcipher 未安装，请运行: brew install sqlcipher"})
    EX.update({"running":True,"progress":0,"status":"","error":""})
    def _do():
        try:
            EX["status"]="解密数据库..."; EX["progress"]=0.05
            plain=_decrypt(db,key)
            EX["status"]="提取消息..."; EX["progress"]=0.15
            msgs=_msgs(plain,marker,lambda p: EX.update({"progress":0.15+p*0.65}))
            Path(out).mkdir(parents=True,exist_ok=True)
            EX["progress"]=0.85
            if fmt in("html","both"):
                EX["status"]="生成 HTML..."
                (Path(out)/"qq_chat.html").write_text(_html(msgs),encoding="utf-8")
            if fmt in("json","both"):
                EX["status"]="生成 JSON..."
                (Path(out)/"qq_messages.json").write_text(
                    json.dumps(msgs,ensure_ascii=False,indent=2),encoding="utf-8")
            EX.update({"progress":1.0,"status":f"完成 {len(msgs):,} 条消息","running":False})
            subprocess.run(["open",out])
        except Exception as e:
            EX.update({"error":str(e),"running":False})
    threading.Thread(target=_do,daemon=True).start()
    return jsonify({"ok":True})

@app.route("/api/export-status")
def export_status(): return jsonify(EX)

@app.route("/api/detect-db")
def detect_db():
    hits=glob.glob(os.path.expanduser(
        "~/Library/Application Support/QQ/nt_qq_*/nt_db/nt_msg.db"))
    return jsonify({"path":hits[0] if hits else ""})

# ── HTML ───────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QQ NT 提取工具</title>
<style>
/* ── Design tokens ─────────────────────────────────────────────── */
:root {
  --paper:  #FAFAF8;
  --ink:    #16181D;
  --jade:   #00A878;
  --alert:  #E5484D;
  --mute:   #8A8A8E;
  --border: rgba(22,24,29,.18);
  --border-strong: rgba(22,24,29,.34);
  --font: 'Inter',-apple-system,'SF Pro Display','Helvetica Neue',sans-serif;
  --mono: 'Menlo','SF Mono','Fira Code',monospace;
  --r: 8px;
}

/* ── Reset & base ──────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
body {
  font-family: var(--font);
  background: var(--paper);
  color: var(--ink);
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
}

/* ── Layout ────────────────────────────────────────────────────── */
.app {
  max-width: 760px;
  margin: 0 auto;
  padding: 48px 24px 80px;
}
header {
  margin-bottom: 40px;
}
header h1 {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.03em;
  margin-bottom: 4px;
}
header p {
  color: var(--mute);
  font-size: 13px;
}

/* ── Tab bar ───────────────────────────────────────────────────── */
.tabs {
  display: flex;
  gap: 0;
  border-bottom: 1.5px solid var(--border);
  margin-bottom: 36px;
}
.tab {
  padding: 10px 20px;
  font-size: 13px;
  font-weight: 500;
  color: var(--mute);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1.5px;
  transition: color .15s, border-color .15s;
  letter-spacing: -0.01em;
}
.tab.active {
  color: var(--ink);
  border-bottom-color: var(--ink);
}
.panel { display: none }
.panel.active { display: block }

/* ── Step cards ────────────────────────────────────────────────── */
.steps { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px }
.step {
  border: 1.5px solid var(--border);
  border-radius: var(--r);
  padding: 20px 24px;
  display: flex;
  align-items: flex-start;
  gap: 20px;
  transition: border-color .2s;
}
.step.active   { border-color: var(--jade) }
.step.done     { border-color: rgba(0,168,120,.3); background: rgba(0,168,120,.03) }
.step.disabled { opacity: .45 }

.step-num {
  width: 28px; height: 28px;
  border-radius: 50%;
  border: 1.5px solid var(--border-strong);
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 600; flex-shrink: 0;
  margin-top: 1px;
}
.step.active  .step-num { border-color: var(--jade); color: var(--jade) }
.step.done    .step-num { border-color: var(--jade); background: var(--jade);
                           color: #fff }
.step.done    .step-num::before { content: "✓" }

.step-body { flex: 1 }
.step-title {
  font-weight: 600;
  letter-spacing: -0.01em;
  margin-bottom: 4px;
}
.step-desc {
  color: var(--mute);
  font-size: 12.5px;
  margin-bottom: 14px;
  line-height: 1.55;
}
.step.done .step-desc { display: none }

/* ── Buttons ───────────────────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 9px 18px;
  border-radius: 6px;
  font-family: var(--font);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: -0.01em;
  cursor: pointer;
  border: none;
  transition: opacity .15s, background .15s;
}
.btn:disabled { opacity: .38; cursor: not-allowed }
.btn-primary  { background: var(--ink); color: var(--paper) }
.btn-primary:hover:not(:disabled) { opacity: .82 }
.btn-ghost {
  background: transparent;
  border: 1.5px solid var(--border-strong);
  color: var(--ink);
}
.btn-ghost:hover:not(:disabled) { background: rgba(22,24,29,.05) }
.btn-jade { background: var(--jade); color: #fff }
.btn-jade:hover:not(:disabled) { opacity: .88 }

/* ── Log terminal ──────────────────────────────────────────────── */
.log-wrap {
  background: #0E1117;
  border-radius: var(--r);
  overflow: hidden;
  margin-bottom: 24px;
}
.log-bar {
  padding: 10px 16px;
  background: #181C24;
  border-bottom: 1px solid rgba(255,255,255,.07);
  font-size: 11px;
  color: rgba(255,255,255,.38);
  font-family: var(--mono);
  letter-spacing: .04em;
  text-transform: uppercase;
}
.log-body {
  padding: 16px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.75;
  color: #C8D3E0;
  min-height: 180px;
  max-height: 260px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.log-body .ok  { color: #50E3A4 }
.log-body .err { color: #FF6B6B }
.log-body .key { color: #FFD700; font-weight: 700 }

/* ── Key result ────────────────────────────────────────────────── */
.key-row {
  display: flex; align-items: center; gap: 12px;
  padding: 16px 20px;
  border: 1.5px solid var(--border);
  border-radius: var(--r);
  margin-bottom: 12px;
  background: #fff;
}
.key-label {
  font-size: 11px; font-weight: 600; letter-spacing: .1em;
  text-transform: uppercase; color: var(--mute); white-space: nowrap;
}
.key-val {
  flex: 1;
  font-family: var(--mono);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: .04em;
  color: var(--jade);
  word-break: break-all;
}
.key-val.empty { color: var(--mute); font-weight: 400; font-size: 13px }

/* ── Form (export) ─────────────────────────────────────────────── */
.form-section { margin-bottom: 28px }
.form-label {
  display: block;
  font-size: 11px; font-weight: 600; letter-spacing: .1em;
  text-transform: uppercase; color: var(--mute);
  margin-bottom: 8px;
}
.field-row {
  display: flex; gap: 8px; align-items: stretch;
}
.field-row input {
  flex: 1;
  padding: 10px 14px;
  border: 1.5px solid var(--border);
  border-radius: 6px;
  font-family: var(--mono);
  font-size: 13px;
  color: var(--ink);
  background: #fff;
  outline: none;
  transition: border-color .15s;
}
.field-row input:focus { border-color: var(--jade) }

.radio-group { display: flex; gap: 16px; flex-wrap: wrap }
.radio-opt {
  display: flex; align-items: center; gap: 6px;
  cursor: pointer; font-size: 13px; font-weight: 500;
}
.radio-opt input { accent-color: var(--jade); width: 15px; height: 15px }

/* ── Progress bar ──────────────────────────────────────────────── */
.progress-wrap {
  background: rgba(22,24,29,.08);
  border-radius: 99px;
  height: 4px;
  margin: 16px 0 8px;
  overflow: hidden;
}
.progress-bar {
  height: 100%;
  background: var(--jade);
  border-radius: 99px;
  transition: width .3s var(--ease, cubic-bezier(.16,1,.3,1));
  width: 0%;
}
.progress-text {
  font-size: 12px; color: var(--mute); min-height: 18px;
}

/* ── Status chip ───────────────────────────────────────────────── */
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px;
  border-radius: 99px;
  font-size: 11.5px; font-weight: 600;
  border: 1.5px solid var(--border);
  color: var(--mute);
}
.chip.ok   { border-color: rgba(0,168,120,.4); color: var(--jade);
             background: rgba(0,168,120,.06) }
.chip.err  { border-color: rgba(229,72,77,.4); color: var(--alert);
             background: rgba(229,72,77,.05) }
.dot {
  width: 6px; height: 6px; border-radius: 50%; background: currentColor;
  animation: pulse 1.4s ease infinite;
}
@keyframes pulse {
  0%,100% { opacity:1 } 50% { opacity:.35 }
}
.chip:not(.ok):not(.err) .dot { animation: none }
</style>
</head>
<body>
<div class="app">

  <header>
    <h1>QQ NT 数据库提取工具</h1>
    <p>macOS Apple Silicon · 无需关闭 SIP · 不修改聊天数据</p>
  </header>

  <nav class="tabs">
    <div class="tab active" onclick="switchTab('key',this)">获取密钥</div>
    <div class="tab" onclick="switchTab('export',this)">导出数据</div>
  </nav>

  <!-- ── 获取密钥 ── -->
  <div id="panel-key" class="panel active">

    <div class="steps" id="steps">

      <div class="step active" id="s1">
        <div class="step-num">1</div>
        <div class="step-body">
          <div class="step-title">对 QQ 重新签名</div>
          <div class="step-desc" id="s1-desc">
            用 ad-hoc 签名替换 QQ 的 hardened runtime，让 lldb 可以附加进程。<br>
            签名前会<strong>自动备份数据库</strong>到 <code>~/qq-extract-backup/</code>，以防万一。<br>
            macOS 会弹出<strong>系统密码框</strong>，输入开机密码即可。
          </div>
          <button class="btn btn-primary" id="btn-sign" onclick="doSign()">签名 QQ</button>
        </div>
      </div>

      <div class="step disabled" id="s2">
        <div class="step-num">2</div>
        <div class="step-body">
          <div class="step-title">启动提取</div>
          <div class="step-desc">
            自动关闭已运行的 QQ，启动 lldb 并重新打开 QQ，等待附加。
          </div>
          <button class="btn btn-primary" id="btn-launch" onclick="doLaunch()" disabled>启动</button>
        </div>
      </div>

      <div class="step disabled" id="s3">
        <div class="step-num">3</div>
        <div class="step-body">
          <div class="step-title">等待密钥</div>
          <div class="step-desc" id="s3-desc">
            工具自动设置断点后，请在 QQ 触发登录：<br>
            <b>情况 A</b>（QQ 显示登录界面）：直接点击「登录」按钮。<br>
            <b>情况 B</b>（QQ 已自动登录显示聊天）：在 QQ 菜单选「退出账号」，返回登录界面后点登录——<b>不要关闭 QQ</b>。
          </div>
          <div id="s3-auto" style="display:none;font-size:13px;color:var(--mute);font-style:italic;margin-top:6px"></div>
        </div>
      </div>

    </div>

    <div class="log-wrap">
      <div class="log-bar">lldb 输出</div>
      <div class="log-body" id="log"></div>
    </div>

    <div class="key-row">
      <span class="key-label">密 钥</span>
      <span class="key-val empty" id="key-display">等待提取...</span>
      <button class="btn btn-ghost" onclick="copyKey()" id="btn-copy" style="display:none">复制</button>
    </div>

  </div><!-- /panel-key -->

  <!-- ── 导出数据 ── -->
  <div id="panel-export" class="panel">

    <div class="form-section">
      <label class="form-label">数据库路径</label>
      <div class="field-row">
        <input type="text" id="db-path" placeholder="自动检测或手动填入...">
        <button class="btn btn-ghost" onclick="detectDb()">自动检测</button>
      </div>
    </div>

    <div class="form-section">
      <label class="form-label">密 钥</label>
      <div class="field-row">
        <input type="text" id="export-key" placeholder="从「获取密钥」自动填入，或手动粘贴..."
               style="font-family:var(--mono)">
      </div>
    </div>

    <div class="form-section">
      <label class="form-label">输出目录</label>
      <div class="field-row">
        <input type="text" id="out-path" value="">
      </div>
    </div>

    <div class="form-section">
      <label class="form-label">导出格式</label>
      <div class="radio-group">
        <label class="radio-opt">
          <input type="radio" name="fmt" value="html" checked> HTML（可直接浏览）
        </label>
        <label class="radio-opt">
          <input type="radio" name="fmt" value="json"> JSON（原始数据）
        </label>
        <label class="radio-opt">
          <input type="radio" name="fmt" value="both"> 两者都要
        </label>
      </div>
    </div>

    <div class="form-section">
      <label class="form-label">气泡方向</label>
      <div class="radio-group">
        <label class="radio-opt">
          <input type="radio" name="marker" value="nt_2" checked> nt_2 = 我的消息（默认）
        </label>
        <label class="radio-opt">
          <input type="radio" name="marker" value="nt_1"> nt_1 = 我的消息（若方向相反时切换）
        </label>
      </div>
    </div>

    <button class="btn btn-primary" onclick="doExport()" id="btn-export"
            style="width:100%;justify-content:center;padding:12px">
      开始导出
    </button>

    <div class="progress-wrap" id="prog-wrap" style="display:none">
      <div class="progress-bar" id="prog-bar"></div>
    </div>
    <div class="progress-text" id="prog-text"></div>

  </div><!-- /panel-export -->

</div><!-- /app -->

<script>
// ── State ──────────────────────────────────────────────────────────────────
let logIdx = 0
let phase = 'idle'
let extractedKey = ''
let pollTimer = null

// ── Tab switch ─────────────────────────────────────────────────────────────
function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'))
  el.classList.add('active')
  document.getElementById('panel-' + name).classList.add('active')
  if (name === 'export' && extractedKey)
    document.getElementById('export-key').value = extractedKey
}

// ── Log rendering ──────────────────────────────────────────────────────────
function appendLog(lines) {
  const el = document.getElementById('log')
  for (const line of lines) {
    const span = document.createElement('span')
    if (line.startsWith('[+]') || line.includes('成功') || line.includes('KEY'))
      span.className = 'ok'
    else if (line.startsWith('[!]') || line.toLowerCase().includes('error') || line.includes('失败'))
      span.className = 'err'
    if (line.includes('KEY    :'))
      span.className = 'key'
    span.textContent = line + '\\n'
    el.appendChild(span)
  }
  el.scrollTop = el.scrollHeight
}

// ── Step UI ────────────────────────────────────────────────────────────────
function setStepDone(id) {
  const s = document.getElementById(id)
  s.className = 'step done'
  s.querySelector('.step-num').textContent = ''
}
function setStepActive(id) {
  const s = document.getElementById(id)
  s.className = 'step active'
}
function setStepDisabled(id) {
  document.getElementById(id).className = 'step disabled'
}

// ── API calls ──────────────────────────────────────────────────────────────
async function doSign() {
  document.getElementById('btn-sign').disabled = true
  document.getElementById('btn-sign').textContent = '签名中...'
  await fetch('/api/sign', {method:'POST'})
  startPoll()
}

async function doLaunch() {
  document.getElementById('btn-launch').disabled = true
  document.getElementById('btn-launch').textContent = '启动中...'
  const r = await fetch('/api/launch', {method:'POST'}).then(r=>r.json())
  if (!r.ok) { alert(r.err); document.getElementById('btn-launch').disabled=false; return }
  startPoll()
}


// ── Poll status ────────────────────────────────────────────────────────────
function startPoll() {
  if (pollTimer) return
  pollTimer = setInterval(poll, 400)
}

async function poll() {
  const r = await fetch('/api/status?since='+logIdx).then(r=>r.json()).catch(()=>null)
  if (!r) return
  if (r.log.length) { appendLog(r.log); logIdx = r.total }
  if (r.phase === phase) return
  phase = r.phase
  applyPhase(phase, r.key)
}

function setS3Auto(msg) {
  const el = document.getElementById('s3-auto')
  if (el) { el.style.display = ''; el.textContent = msg }
}

function applyPhase(ph, key) {
  if (ph === 'signed') {
    setStepDone('s1')
    const desc = document.getElementById('s1-desc')
    if (desc) desc.innerHTML = '✓ 已检测到 QQ 为 ad-hoc 签名，无需重新签名'
    document.getElementById('btn-sign').style.display = 'none'
    setStepActive('s2')
    document.getElementById('btn-launch').disabled = false
  }
  if (ph === 'launching' || ph === 'attached') {
    setStepDone('s1')
    setStepDone('s2')
    setStepActive('s3')
    setS3Auto('lldb 正在附加 QQ 进程...')
  }
  if (ph === 'running') {
    setStepDone('s1')
    setStepDone('s2')
    setStepActive('s3')
    setS3Auto('QQ 已启动，正在等待断点设置...')
  }
  if (ph === 'interrupting') {
    setStepActive('s3')
    setS3Auto('正在暂停 QQ、设置断点...')
  }
  if (ph === 'waiting') {
    setStepActive('s3')
    const desc = document.getElementById('s3-desc')
    if (desc) desc.style.display = 'none'
    setS3Auto('✓ 断点已就绪 — 若 QQ 显示登录界面，点「登录」；若已自动登录，请退出账号后重新登录（不关闭 QQ）')
  }
  if (ph === 'done' && key) {
    extractedKey = key
    setStepDone('s1'); setStepDone('s2'); setStepDone('s3')
    const kd = document.getElementById('key-display')
    kd.textContent = key; kd.className = 'key-val'
    document.getElementById('btn-copy').style.display = ''
    document.getElementById('export-key').value = key
    clearInterval(pollTimer); pollTimer = null
  }
}

function copyKey() {
  navigator.clipboard.writeText(extractedKey)
  const b = document.getElementById('btn-copy')
  b.textContent = '已复制'; setTimeout(()=>b.textContent='复制', 1500)
}

// ── Export ─────────────────────────────────────────────────────────────────
async function detectDb() {
  const r = await fetch('/api/detect-db').then(r=>r.json())
  const inp = document.getElementById('db-path')
  if (r.path) {
    inp.value = r.path
    inp.style.color = 'var(--jade)'
    setTimeout(() => inp.style.color = '', 1200)
  } else {
    inp.placeholder = '未检测到，请手动填入路径'
  }
}

async function doExport() {
  const db  = document.getElementById('db-path').value.trim()
  const key = document.getElementById('export-key').value.trim()
  const out = document.getElementById('out-path').value.trim()
  const fmt = document.querySelector('input[name="fmt"]:checked').value
  const marker = document.querySelector('input[name="marker"]:checked').value

  const r = await fetch('/api/export', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({db,key,out,fmt,marker})
  }).then(r=>r.json())

  if (!r.ok) { alert(r.err); return }

  document.getElementById('btn-export').disabled = true
  document.getElementById('prog-wrap').style.display = ''
  pollExport()
}

async function pollExport() {
  const r = await fetch('/api/export-status').then(r=>r.json())
  document.getElementById('prog-bar').style.width = (r.progress*100)+'%'
  document.getElementById('prog-text').textContent = r.error
    ? '错误：' + r.error : r.status
  if (r.running || (!r.error && r.progress < 1)) {
    setTimeout(pollExport, 500)
  } else {
    document.getElementById('btn-export').disabled = false
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
fetch('/api/detect-db').then(r=>r.json()).then(r => {
  if (r.path) {
    document.getElementById('db-path').value = r.path
    const parts = r.path.split('/')
    if (parts.length >= 3 && !document.getElementById('out-path').value)
      document.getElementById('out-path').value = '/' + parts[1] + '/' + parts[2] + '/Desktop'
  }
})

fetch('/api/status?since=0').then(r=>r.json()).then(r => {
  // 服务器启动时已探测签名状态，直接用服务器的 phase 驱动 UI
  applyPhase(r.phase, r.key)
  phase = r.phase
  if (r.phase !== 'idle' && r.phase !== 'signed' && r.phase !== 'done')
    startPoll()
})
</script>
</body>
</html>"""

# ── 启动 ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 默认输出目录通过 js 设置，但服务端给个 Desktop 兜底
    import datetime
    default_out = str(Path.home() / "Desktop")

    PORT = 8899
    print(f"[QQ 提取工具] http://127.0.0.1:{PORT}")
    threading.Timer(0.8, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
