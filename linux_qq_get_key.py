#!/usr/bin/env python3

import subprocess
import re
import hashlib
from pathlib import Path

QQ_CONFIG = Path.home() / '.config' / 'QQ'
WRAPPER_NODE_PATH = '/opt/QQ/resources/app/wrapper.node'

def error(msg):
    print(f"\033[1;31m Error: {msg}\033[0m")
    exit(1)

def Assert(condition, msg):
    if not condition:
        error(msg)

# get Program Header and Section Mapping
result = subprocess.run(["readelf", "-lW" , WRAPPER_NODE_PATH], stdout = subprocess.PIPE, text= True)
output = result.stdout
program_header = []
rodata_info = None
read_program_header = False
read_section_mapping = False
re_ph = re.compile(r"\s*(\w+)\s+0x(\d+)\s+0x(\d+).*")
re_mp = re.compile(r"\s*(\d+)\s+(.*)")
for line in output.splitlines():
    line = line.strip()
    if "Program Headers:" in line:
        read_program_header = True
        continue
    if "Section to Segment mapping:" in line:
        read_program_header = False
        read_section_mapping = True
        continue
    if read_program_header:
        m = re_ph.match(line)
        if m:
            program_header.append({
                "type": m.group(1),
                "section_offset": int(m.group(2), 16),
                "virt_addr": int(m.group(3), 16)
            })
    if read_section_mapping:
        m = re_mp.match(line)
        if m:
            (idx , sections) = m.groups()
            if ".rodata" in sections:
                rodata_info = program_header[int(idx)]
                break

Assert(rodata_info is not None, "rodata section not found")
print(f"rodata_info: {rodata_info}")

# get string offset
result = subprocess.Popen(["strings", "-t" , "d" , WRAPPER_NODE_PATH], stdout = subprocess.PIPE, text= True)
pattern = re.compile('nt_sqlite3_key_v2: db=%p zDb=%s$')
for line in result.stdout:
    line = line.strip()
    if(pattern.search(line)):
        offset = line.split(" ")[0]
        Assert(offset.isdecimal(), "offset should be decimal")
        result.terminate()
        break
str_off = int(offset)
print(f"str_off offset: {hex(str_off)}")

# get reference offset

def get_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

ref_off_cache_file = Path.cwd() / 'ref_off_cache'
shoud_recalculate = True
if(Path.exists(ref_off_cache_file)):
    with open(ref_off_cache_file, 'r') as f:
        try:
            file_hash = f.readline().strip()
            ref_off = list(map(str, f.readline().strip().split()))
            shoud_recalculate = file_hash != get_file_hash(WRAPPER_NODE_PATH) or len(ref_off) == 0
        except Exception as e:
            print(f"Error: {e}\n recalculate ref_off")
            

if(shoud_recalculate):
    result = subprocess.Popen(["objdump", "-D" , "-j" , ".text" , WRAPPER_NODE_PATH], stdout = subprocess.PIPE, text= True)
    str_addr = rodata_info["virt_addr"] + str_off - rodata_info["section_offset"]
    pattern = re.compile(f".*# {str_addr:x}")
    ref_off = []
    for line in result.stdout:
        line = line.strip()
        if(pattern.search(line)):
            offset = line.split(":")[0]
            Assert(re.match(r'[0-9a-f]+', offset), "offset should be hex")
            ref_off.append(offset)
    result.terminate()
    with open(ref_off_cache_file, 'w') as f:
        f.write(f"{get_file_hash(WRAPPER_NODE_PATH)}\n")
        f.write(" ".join(map(str, ref_off)) + "\n")

print(f"ref_off offset: {ref_off}")

import gdb

def exit_gdb():
    gdb.execute("set confirm off")
    gdb.execute("quit")

hook_stop_script = """
define hook-stop
x /10i $pc
p (char[16])*(char *)$rsi
p $rdx
end
"""
gdb.execute(hook_stop_script, to_string=True)
gdb.execute("set pagination off")

# load wrapper.node
gdb.execute("break dlopen")
gdb.execute("run")
finish = False
i = 20
while not finish:
    output = gdb.execute("x /s file", to_string=True)
    if i == 0:
        finish = True
    if "wrapper.node" in output:
        break
    gdb.execute("continue")
gdb.execute("finish")

output = gdb.execute("info proc mappings", to_string=True)
base_addr = None
for line in output.splitlines():
    if "wrapper" in line:
        base_addr= int(line.split()[0],16)
        break
print(f"Base address found: {base_addr}")

# find function address
breakpoints = []
gdb.execute("delete breakpoints")
for ref in ref_off:
    breakpoint_addr = base_addr + int(ref, 16)
    gdb.execute(f"break *{breakpoint_addr}")
    gdb.execute(f"x /10i {breakpoint_addr}")


gdb.execute("continue")
gdb.execute("finish")

func_addr = None
for i in range(16):
    inst = gdb.execute(f"x /i $pc - {i}", to_string=True)
    if "call" in inst:
        func_addr = int(inst.split(" ")[-1], 16)
        break

if func_addr is None:
    print("Function address not found.")
    exit_gdb()

print(f"func_addr: {hex(func_addr)}")
#get zDb
gdb.execute("delete breakpoints")
gdb.execute(f"break *{func_addr}")
gdb.execute(f"continue")
while(gdb.parse_and_eval("$rdx") != 16):
    gdb.execute("continue")
zDb = gdb.parse_and_eval("(char[16])*(char *)$rsi")
print(f"zDb: {zDb}")

exit_gdb()