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


generalident = "FF 03 02 D1 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 7B 07 A9 FD C3 01 91 58 D0 3B D5 08 17 40 F9 F3 03 00 AA F4 03 01 AA E8 1F 00 F9 64 2A 40 B9 E4 04 00 34 68 1A 40 F9"
funcident = {
    "8.9.76": generalident,
}


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in funcident:
        print("usage: qq.version.number")
        print("supported version:", *funcident.keys())
        sys.exit(1)

    print("仍在测试。")
    print("请先关闭 Magisk Hide 与 Shamiko")
    print("请先禁用 SELinux")
    print(
        "请先打开 QQ 并登录，进入主界面，然后运行该脚本，等待数秒后退出登录并重新登录。"
    )
    print("若失败，可尝试彻底关闭 QQ 后直接运行")
    print("理论支持 Termux 与 桌面操作系统 运行")
    print("请勿使用 x86 或 x64 系统上的安卓模拟器。")
    print(
        """Termux 环境具体命令：
    sudo friendly # 重命名后的 frida-server
    python android_hook.py
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
    with open("android_get_backup_key.js", "rb") as f:
        jscode1 = f.read().decode()
    jscode1 = jscode1.replace("__single_function__parameter__", funcident[sys.argv[1]])
    if running:
        print(PACKAGE + " is already running", pid)
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
            toprint = message["payload"]
        else:
            toprint = message
        toprint = str(toprint)
        # toprint=str(list(toprint))
        print(toprint)

    script.on("message", on_message)
    script.load()
    print("Frida script injected.")
    sys.stdin.read()
