from typing import Optional
import frida
import sys
import platform
import os
import functools
import subprocess

# OPTIONS

PACKAGE = "com.tencent.mobileqq"

# OPTIONS END

@functools.cache
def isOnTermux() -> bool:
    if (
        platform.system() == "Linux"
        and "ANDROID_ROOT" in os.environ.keys()
        and (
            os.path.exists("/data/data/com.termux")
            or ("TERMUX_VERSION" in os.environ.keys())
        )
    ):
        return True
    return False


general_script = """
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
            send("定位函数使用的序列： " + pattern)
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

        const key_v2_function = single_function("FD 7B BD A9 F6 57 01 A9 F4 4F 02 A9 FD 03 00 91 F6 03 01 AA F5 03 00 AA ?? ?? ?? ?? F3 03 03 2A F4 03 02 AA")

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

version_scripts = {
    "8.9.58": general_script,
    "8.9.63": general_script,
    "8.9.68": general_script,
    "8.9.76": general_script,
}

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("用法: [qq.version.number]")
        print("支持的版本:", *version_scripts.keys())
        print("例:", __file__, "8.9.58")
        sys.exit(1)
    jscode = general_script
    if len(sys.argv) == 2 and sys.argv[1] in version_scripts.keys():
        jscode = version_scripts[sys.argv[1]]
    else:
        print("使用默认版本注入脚本")

    print("仍在测试...")
    print("请先关闭 Magisk Hide 与 Shamiko")
    print("请先禁用 SELinux")
    print(
        "请先打开 QQ 并登录，进入主界面，然后运行该脚本，等待数秒后退出登录并重新登录。"
    )
    print("若失败，可尝试彻底关闭 QQ 后直接运行")
    print("理论支持 Termux 与 桌面操作系统 运行")
    print("请勿使用 x86 或 x64 系统上的安卓模拟器。")
    print("适用版本：")
    print("https://downv6.qq.com/qqweb/QQ_1/android_apk/qq_8.9.58.11050_64.apk")
    print("https://github.com/QQBackup/QQ-History-Backup/issues/9")
    print(
        """Termux 环境具体命令：
    sudo friendly # 重命名后的 frida-server
    python android_get_key.py
    """
    )

    if isOnTermux():
        device = frida.get_remote_device()
        pid_command = f"su -c 'pidof {PACKAGE}'"
    else:
        device = frida.get_usb_device()
        pid_command = f"adb shell su -c 'pidof {PACKAGE}'"
    running = True
    try:
        pid = int(
            subprocess.check_output(pid_command, shell=True)
            .decode()
            .strip()
            .split(" ")[0]
        )
    except:
        running = False
    if running:
        print(PACKAGE + " is already running", pid)
        session = device.attach(pid)
        script = session.create_script(jscode)
    else:
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
        script = session.create_script(jscode)
        device.resume(pid)
    print("QQ running!! pid = %d" % pid)

    def on_message(message, data):
        if message["type"] == "send":
            toprint = message["payload"]
        else:
            toprint = message
        toprint = str(toprint)
        print(toprint)

    script.on("message", on_message)
    script.load()
    print("Frida script injected.")
    sys.stdin.read()
