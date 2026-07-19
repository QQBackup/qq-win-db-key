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
const module_name = "libbasic_share.so"

function hook(){
    /*
     * https://codeshare.frida.re/@oleavr/read-std-string/
     * Note: Only compatible with libc++, though libstdc++'s std::string is a lot simpler.
     */
    
    function readStdString (str) {
      const isTiny = (str.readU8() & 1) === 0;
      if (isTiny) {
        return str.add(1).readUtf8String();
      }
      return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
    }
    
    var result_addr;
    
    const upd = {
        onEnter: function(args) {
            // console.log('Backtrace 1:\\n' + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            console.log('update param ->', args[1].readCString(args[2].toInt32()));
            // result_addr = args[1]
            // console.log("¦- *zDb: " + args[0].readCString());
            }
        }
    const ggg = {
        onLeave: function(ret) {console.log('MD5:', readStdString(ret))}
    }
    // Interceptor.attach(Module.findBaseAddress('libkernel.so').add(0x1b394e0), ggg);
    
    //Interceptor.attach(Module.findExportByName(module_name, '_ZN4xpng8SHA1HashEPKhm'), ggg);
    //Interceptor.attach(Module.findExportByName(module_name, 'SHA256_Update'), ggg);
    Interceptor.attach(Module.findExportByName(module_name, '_ZN4xpng9MD5UpdateEPA88_cPKhm'), upd);
    ///////// Interceptor.attach(Module.findExportByName(module_name, '_ZN4xpng8MD5FinalEPNS_9MD5DigestEPA88_c'), ggg);
    Interceptor.attach(Module.findExportByName(module_name, '_ZN4xpng17MD5DigestToBase16ERKNS_9MD5DigestE'), ggg);
    //Interceptor.attach(Module.findExportByName('libxplatform.so', '_ZN2xp3md55CRC32EjPKhi'), ggg);
}


var hasHooked = false;
console.log("Script loaded. Waiting for " + module_name + " to load...");
const dlopen_process = {
  onEnter: function (args) {
    this.path = Memory.readUtf8String(args[0]);
    if (0) console.log("Loading " + this.path);
  },
  onLeave: function (retval) {
    if (this.path.indexOf(module_name) !== -1 && !hasHooked) {
      hasHooked = true;
      if (1) console.log("Hooked!!");
      hook();
    }
  },
};

try {
  Interceptor.attach(Module.findExportByName(null, "dlopen"), dlopen_process);
} catch (err) {}
try {
  Interceptor.attach(
    Module.findExportByName(null, "android_dlopen_ext"),
    dlopen_process
  );
} catch (err) {}

"""

if __name__ == "__main__":
    jscode = general_script

    if isOnTermux():
        device = frida.get_remote_device()
        pid_command = f"su -c 'pidof {PACKAGE}'"
    else:
        device = frida.get_usb_device()
        pid_command = f"adb shell su -c 'pidof {PACKAGE}'"
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)
    script = session.create_script(jscode)
    device.resume(pid)
    print("QQ running!! pid = %d" % pid)

    def on_message(message, data):
        print(message)

    script.on("message", on_message)
    script.load()
    print("Frida script injected.")
    sys.stdin.read()
    