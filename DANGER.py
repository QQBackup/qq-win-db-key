print("这货不能用，文件还是加密的，而且理论上可能会损坏原数据库，别用！")
exit()

import frida
import sys
import psutil
import shutil
import time
import os

QQ_PID = None
# GUI -> ['C:\\Program Files (x86)\\Tencent\\QQ\\Bin\\QQ.exe']
# 要hook的 -> ['C:\\Program Files (x86)\\Tencent\\QQ\\Bin\\QQ.exe', '/hosthwnd=2164594', '/hostname=QQ_IPC_{12345678-ABCD-12EF-9976-18373DEAB821}', '/memoryid=0', 'C:\\Program Files (x86)\\Tencent\\QQ\\Bin\\QQ.exe']
for pid in psutil.pids():
    p = psutil.Process(pid)
    if p.name() == "QQ.exe" and len(p.cmdline()) > 1:
        QQ_PID = pid
        del p
        break

if QQ_PID is None:
    print("QQ not launched. exit.")
    sys.exit(1)
print("QQ pid is:", QQ_PID)
demo_script = """
var pMessageBoxW = Module.findExportByName("user32.dll", 'MessageBoxA')
var lpText = Memory.allocAnsiString("I'm New MessageBox");
var funMsgBox = new NativeFunction(pMessageBoxW, 'uint32',['uint32','pointer','pointer','uint32']);

funMsgBox(0, ptr(lpText), ptr(lpText), 0);
"""
hook_script = """
function buf2hex(buffer) {
  const byteArray = new Uint8Array(buffer);
  const hexParts = [];
  for(let i = 0; i < byteArray.length; i++) {
    const hex = byteArray[i].toString(16);
    const paddedHex = ('00' + hex).slice(-2);
    hexParts.push(paddedHex);
  }
  return '0x' + hexParts.join(', 0x');
}

const kernel_util = Module.load('KernelUtil.dll');
function single_function(pattern) {
    pattern = pattern.replaceAll("##", "").replaceAll(" ", "").toLowerCase().replace(/\s/g,'').replace(/(.{2})/g,"$1 ");
    var akey_function_list = Memory.scanSync(kernel_util.base, kernel_util.size, pattern);
    if (akey_function_list.length > 1) {
        send("pattern FOUND MULTI!!")
        send(pattern)
        send(akey_function_list)
        send("!!exit")
    }
    if (akey_function_list.length == 0) {
        send("pattern NOT FOUND!!")
        send("!!exit")
    }
    return akey_function_list[0]['address'];
}

// const key_function = Module.findExportByName("KernelUtil.dll", 'sqlite3_key')
const key_function = single_function("55 8b ec 56 6b 75 10 11 83 7d 10 10 74 0d 68 17 02 00 00 e8")
const name_function = single_function("55 8B EC FF 75 0C FF 75 08 E8 B8 D1 02 00 59 59 85")
const rekey_function = single_function("##558BEC837D1010740D682F020000E8")
const close_function = single_function("##55 8B EC 56 8B  75 08 85 F6 74 6D 56 E87C 3E 01 00")
// send(key_function)
var name_function_caller = new NativeFunction(name_function, 'pointer', ['pointer', 'pointer']);
var rekey_function_caller = new NativeFunction(rekey_function, 'int', ['pointer', 'pointer', 'int']);
var close_function_caller = new NativeFunction(close_function, 'int', ['pointer', 'int']);
var TARGET_KEY_LENGTH = 16;
var key_length = 0;
var empty_password = Memory.alloc(TARGET_KEY_LENGTH)
empty_password.writeByteArray(Array(TARGET_KEY_LENGTH).fill(0))


Interceptor.attach(key_function, {
    onEnter: function (args, state) {
    
        console.log("[+] key found:");
        var dbName = name_function_caller(args[0], NULL).readUtf8String();
        if (dbName.replaceAll('/', '\\\\').split('\\\\').pop().toLowerCase() == 'Msg3.0.db'.toLowerCase() || false) {
            //console.log("¦- db: " + args[0]);
            key_length = args[2].toInt32()
            console.log("¦- nKey: " + key_length);
            //console.log("¦- pkey: " + args[1]);
            console.log("¦- *pkey: " + buf2hex(args[1].readByteArray(key_length)));
            console.log("¦- dbName: " + name_function_caller(args[0], NULL).readUtf8String());
            //console.log("¦- *pkey: " + buf2hex(Memory.readByteArray(new UInt64(args[1]), key_length)));
            if(key_length == TARGET_KEY_LENGTH){
                console.log(rekey_function_caller(args[0], empty_password, key_length))
                // console.log(close_function_caller(args[0], 0))
                send("!!MSG3.0: " + dbName)
                console.log(rekey_function_caller(args[0], args[1], key_length))
            }
        }
    },
    
    onLeave: function (retval, state) {
    }

});
"""

session = frida.get_local_device().attach(QQ_PID)
script = session.create_script(hook_script)

def on_message(message, data):
    if message['type'] == 'send':
        if message['payload'] == "!!exit":
            exit(3)
        if message['payload'].startswith("!!MSG3.0: "):
            filename = message['payload'][10:]
            new_filename = filename.split("\\")[-1] + "_" + str(time.time()) + ".db"
            print("Copying decrypted file:", filename, "to", new_filename)
            file1 = open(message['payload'][10:], "rb")
            # generate in current folder, remove full file path, with time
            file2 = open(new_filename, "wb")
            # detect extra sqlite header "SQLite header 3"
            file1.seek(0)
            extra_flag = False
            if file1.read(15) == b"SQLite header 3":
                file1.seek(1024)
                if file1.read(15) == b"SQLite format 3":
                    file1.seek(1024)
                    extra_flag = True
            if not extra_flag:
                file1.seek(0)
            file2.write(file1.read())
            file1.close()
            file2.close()
        else:
            print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

def on_destroyed():
    print("process exited.")
    os._exit(0)

script.on('message', on_message)
script.on('destroyed', on_destroyed)
script.load()
print("hooked.")
sys.stdin.read()
