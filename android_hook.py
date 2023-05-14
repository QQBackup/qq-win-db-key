# OPTIONS

PACKAGE = "com.tencent.mobileqq"

# OPTIONS END

print("仍在测试。")
print("请先关闭 Magisk Hide 与 Shamiko")
print("可能需要禁用 SELinux")
print("理论支持 Termux 与 桌面操作系统 运行")
print("请勿使用 x86 或 x64 系统上的安卓模拟器。")
print("适用版本：")
print("https://downv6.qq.com/qqweb/QQ_1/android_apk/qq_8.9.58.11050_64.apk")
print("https://github.com/Young-Lord/QQ-History-Backup/issues/9")

print("")

print("可能需要彻底关闭 QQ 后运行，或者运行后重新登录")
import frida
import sys
import time
import platform
import os

ON_TERMUX: bool = None
def isOnTermux() -> bool:
    global ON_TERMUX
    if ON_TERMUX is not None:
        return ON_TERMUX
    if platform.system() == "Linux"\
        and "ANDROID_ROOT" in os.environ.keys()\
        and (os.path.exists("/data/data/com.termux")
             or ("TERMUX_VERSION" in os.environ.keys())):
        ON_TERMUX = True
        return True
    ON_TERMUX = False
    return False


jscode1 = """
const module_name = "libkernel.so"
const dump_dest = "/data/local/tmp/dump.db"
function hook(){
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
    var kernel_util = null;
    var process_Obj_Module_Arr = Process.enumerateModules();
    for(var i = 0; i < process_Obj_Module_Arr.length; i++) { 
    if(process_Obj_Module_Arr[i].path.indexOf("libkernel.so")!=-1)   {
        console.log("模块名称:",process_Obj_Module_Arr[i].name);
        console.log("模块地址:",process_Obj_Module_Arr[i].base);
        console.log("大小:",process_Obj_Module_Arr[i].size);
        console.log("文件系统路径",process_Obj_Module_Arr[i].path);
        kernel_util = process_Obj_Module_Arr[i];
    }}
    if(kernel_util == null){
        send("libkernel.so not loaded. exit.")
        raise_a_error()
    }

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
    
    const name_function = single_function("FD 7B BE A9 F4 4F 01 A9FD 03 00 91 F3 03 01 AA  AE 00 00 94 60 01 00 34")
    const key_v2_function = single_function("FD 7B BD A9 F5 0B 00 F9F4 4F 02 A9 FD 03 00 91  F4 03 01 AA F5 03 00 AA")
    var funcName = new NativeFunction(name_function, 'pointer', ['pointer', 'pointer']);
    Interceptor.attach(key_v2_function, {
        onEnter: function(args) {
            var dbName = funcName(args[0], NULL).readUtf8String();
            if (dbName.replaceAll('/', '\\\\').split('\\\\').pop().toLowerCase() == 'nt_msg.db'.toLowerCase() || false) {
                //console.log("¦- db: " + args[0]);
                console.log("¦- nKey: " + args[3].toInt32());
                //console.log("¦- pkey: " + args[2]);
                console.log("¦- *pkey: " + buf2hex(args[2].readByteArray(args[3].toInt32())));
                console.log("¦- dbName: " + funcName(args[0], NULL).readUtf8String());
                console.log("¦- *zDb: " + args[1].readUtf8String());
                //console.log("¦- *pkey: " + buf2hex(Memory.readByteArray(new UInt64(args[2]), args[3])));
            }
        }
    });
}

var hasHooked = false;
send("Script loaded. Waiting for "+module_name+" to load...")
const dlopen_process = {
    onEnter: function (args) {
        this.path = Memory.readUtf8String(args[0])
        if (0) send("Loading " + this.path);
    },
    onLeave: function (retval) {
        if (this.path.indexOf(module_name) !== -1 && !hasHooked) {
            hasHooked = true;
            if (1) send("Hooked!!");
            hook();
        }
    }
}
try { Interceptor.attach(Module.findExportByName(null, "dlopen"), dlopen_process); } catch(err) { }
try { Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), dlopen_process); } catch(err) { }
"""

if __name__ == "__main__":
    if isOnTermux():
        device = frida.get_remote_device()
    else:
        device = frida.get_usb_device()
    pid = device.spawn(["PACKAGE"])
    session = device.attach(pid)
    script = session.create_script(jscode1)
    device.resume(pid)
    print("QQ start running!! pid = %d" % pid)
    
    def on_message(message, data):
        if message["type"] == "send":
            toprint=message["payload"]
        else:
            toprint=message
        toprint=str(toprint)
        #toprint=str(list(toprint))
        print(toprint)
    script.on("message", on_message)
    script.load()
    print("Frida script injected.")
    sys.stdin.read()
