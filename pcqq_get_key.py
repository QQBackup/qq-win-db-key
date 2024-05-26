import frida
import sys
import psutil

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
    pattern = pattern.replaceAll("##", "").replaceAll(" ", "").toLowerCase().replace(/\\s/g,'').replace(/(.{2})/g,"$1 ");
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
// send(key_function)
var funcName = new NativeFunction(name_function, 'pointer', ['pointer', 'pointer']);


Interceptor.attach(key_function, {
    onEnter: function (args, state) {
    
        console.log("[+] key found:");
        var dbName = funcName(args[0], NULL).readUtf8String();
        if (dbName.replaceAll('/', '\\\\').split('\\\\').pop().toLowerCase() == 'Msg3.0.db'.toLowerCase() || false) {
            //console.log("¦- db: " + args[0]);
            console.log("¦- nKey: " + args[2].toInt32());
            //console.log("¦- pkey: " + args[1]);
            console.log("¦- *pkey: " + buf2hex(args[1].readByteArray(args[2].toInt32())));
            console.log("¦- dbName: " + funcName(args[0], NULL).readUtf8String());
            //console.log("¦- *pkey: " + buf2hex(Memory.readByteArray(new UInt64(args[1]), args[2])));
        }
    },
    
    onLeave: function (retval, state) {
    }

});
"""

session = frida.get_local_device().attach(QQ_PID)
script = session.create_script(hook_script)


def on_message(message, data):
    if message["type"] == "send":
        if message["payload"] == "!!exit":
            exit(3)
        print(message["payload"])
    elif message["type"] == "error":
        print(message["stack"])


def on_destroyed():
    print("process exited.")
    sys.exit(0)


script.on("message", on_message)
script.on("destroyed", on_destroyed)
script.load()
print("hooked.")
sys.stdin.read()
