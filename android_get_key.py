import frida
import sys
import platform
import os
import sys
import subprocess

# OPTIONS

PACKAGE = "com.tencent.mobileqq"

# OPTIONS END

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

generalident = 'FD 7B BD A9 F6 57 01 A9 F4 4F 02 A9 FD 03 00 91 F6 03 01 AA F5 03 00 AA ?? ?? ?? ?? F3 03 03 2A F4 03 02 AA'
funcident = {
    '8.9.58': generalident,
    '8.9.63': generalident,
    '8.9.68': generalident,
    '8.9.76': generalident,
}


jscode1 = """
const module_name = "libkernel.so"

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
    function buf2str(buffer) {
        let result = "";
        const byteArray = new Uint8Array(buffer);
        for (let i = 0; i < byteArray.length; i++) {
            result += String.fromCharCode(byteArray[i]);
        }
        return result;
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
    if(kernel_util == null) {
        send("libkernel.so not loaded. exit.")
    } else {
        function single_function(pattern) {
            pattern = pattern.replaceAll("##", "").replaceAll(" ", "").toLowerCase().replace(/\\s/g,'').replace(/(.{2})/g,"$1 ");
            send("Pattern: " + pattern)
            var akey_function_list = Memory.scanSync(kernel_util.base, kernel_util.size, pattern);
            if (akey_function_list.length == 0) {
                send("Pattern NOT FOUND!! EXIT!!")
                return null;
            }
            if (akey_function_list.length > 1) {
                send("Multi-pattern FOUND!! Take first item.")
            }
            send("Attach key_v2_function addr: " + akey_function_list[0]['address'])
            return akey_function_list[0]['address'];
        }

        const key_v2_function = single_function("__single_function__parameter__")

        if(key_v2_function != null) Interceptor.attach(key_v2_function, {
            onEnter: function(args) {
                let nk = args[3].toInt32();
                let pk = args[2].readByteArray(nk);
                console.log("¦- targetDB: " + args[0]);
                console.log("¦- *zDb: " + args[1].readUtf8String());
                console.log("¦- *pkey: " + buf2str(pk));
                console.log("¦- *pkey-hex: " + buf2hex(pk));
                console.log("¦- nKey: " + nk);
            },
        });
    }
}

hook()
"""

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in funcident:
        print("usage: qq.version.number")
        print("supported version:", *funcident.keys())
        sys.exit(1)

    print("仍在测试。")
    print("请先关闭 Magisk Hide 与 Shamiko")
    print("请先禁用 SELinux")
    print("请先打开 QQ 并登录，进入主界面，然后运行该脚本，等待数秒后退出登录并重新登录。")
    print("理论支持 Termux 与 桌面操作系统 运行")
    print("请勿使用 x86 或 x64 系统上的安卓模拟器。")
    print("适用版本：")
    print("https://downv6.qq.com/qqweb/QQ_1/android_apk/qq_8.9.58.11050_64.apk")
    print("https://github.com/Young-Lord/QQ-History-Backup/issues/9")
    print("""Termux 环境具体命令：
    sudo friendly # 重命名后的 frida-server
    python android_hook.py""")
    print("")
    print("可能需要彻底关闭 QQ 后运行，或者运行后重新登录")

    if isOnTermux():
        device = frida.get_remote_device()
    else:
        device = frida.get_usb_device()
    try:
        pid = int(subprocess.check_output(
                "su -c pidof "+PACKAGE, shell=True).decode().strip()
            ) if ON_TERMUX else device.get_frontmost_application().pid
    except subprocess.CalledProcessError:
        running = False
    else:
        running = True
    jscode1 = jscode1.replace("__single_function__parameter__", funcident[sys.argv[1]])
    if running:
        print(PACKAGE+" is already running", pid)
        session = device.attach(pid)
        script = session.create_script(jscode1)
    else:
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
        script = session.create_script(jscode1)
        device.resume(pid)
    print("QQ running!! pid = %d" % pid)
    
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
