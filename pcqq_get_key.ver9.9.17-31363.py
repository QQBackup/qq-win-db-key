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

function read_bytes(address, size) {
    let addr = ptr(address);
    let bytes = Memory.readByteArray(addr, size);

    let hexString = [...new Uint8Array(bytes)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(' ');

    console.log("Bytecode at " + addr + ":");
    console.log("Bytecode: " + hexString);
}

function read_bytes_as_char(address, size) {
    let addr = ptr(address);

    try {
        let bytes = Memory.readByteArray(addr, size);
        let byteArray = new Uint8Array(bytes);

        let charString = "";

        for (let i = 0; i < byteArray.length; i++) {
            let byte = byteArray[i];
            charString += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : ".";
        }

        console.log(`Memory at ${addr} (${size} bytes as chars): ${charString}`);
    } catch (e) {
        console.log("Error: " + e);
    }
}

function read_utf8_string(address) {
    let strPtr = ptr(address);
    try {
        let str = Memory.readUtf8String(strPtr);
        console.log(str);
    } catch (e) {
    }
}

function get_utf8_string(address) {
    let strPtr = ptr(address);
    try {
        let str = Memory.readUtf8String(strPtr);
        return str;
    } catch (e) {
        return "";
    }
}

function str_add(s, n) {
    return "0x" + (parseInt(s, 16) + n).toString(16)
}

function single_function(pattern, mod) {
    const kernel_util = Module.load(mod);
    pattern = pattern.replaceAll("##", "").replaceAll(" ", "").toLowerCase().replace(/\\s/g,'').replace(/(.{2})/g,"$1 ");

    
    if (mod == "wrapper.node") {
        console.log(kernel_util.size, kernel_util.size-104493056)
        // console.log(str_add(kernel_util.base, 41180400))
        // read_bytes(str_add(kernel_util.base, 41180272), 32)
        // read_bytes(str_add(kernel_util.base, 41180400), 32)
        var akey_function_list = Memory.scanSync(kernel_util.base, 0x6000000, pattern);
    } else {
        var akey_function_list = Memory.scanSync(kernel_util.base, kernel_util.size, pattern);
    }

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
    if (akey_function_list.length == 1) {
        send(mod + " pattern FOUND!!")
        send(pattern)
        send(akey_function_list)
        send(akey_function_list[0]['address'])
        
        read_bytes(akey_function_list[0]['address'], 16)

        return akey_function_list[0]['address'];
    }
}

let mods = ["wrapper.node"]

//  key_function_addr : 41 56 56 57 53 48 83 EC 28 44 89 CE 4C 89 C7 49 89 D6 48 89 CB 48 8D 15 17 D3 65 01 B9 08 00 00
// name_function_addr : 41 56 56 57 53 48 83 EC 28 31 F6 48 85 D2 74 2D 8B 59 30 85 DB 7E 26 48 89 D7 4C 8B 71 28 31 F6

    let i = 0
    const key_function_addr  = single_function("41 56 56 57 53 48 83 ec 28 44 89 ce 4c 89 c7 49 89 d6 48 89 cb 48 8d 15 17 d3 65 01 b9 08 00 00", mods[i]);
    const name_function_addr = single_function("41 56 56 57 53 48 83 EC 28 31 F6 48 85 D2 74 2D 8B 59 30 85 DB 7E 26 48 89 D7 4C 8B 71 28 31 F6", mods[i]);

    var nameFunc = new NativeFunction(name_function_addr, 'pointer', ['pointer', 'pointer']);

    Interceptor.attach(key_function_addr, {
        onEnter: function (args, state) {
            read_bytes_as_char(args[2], 16)
        },

        onLeave: function (retval, state) {
        }
    });
"""

import frida
import sys
import psutil

def on_message(message, data):
    if message["type"] == "send":
        if message["payload"] == "!!exit":
            exit(3)
            pass
        print('[*]', message["payload"])
    elif message["type"] == "error":
        print('[stack]', message["stack"])

def on_destroyed():
    print('[*]', "process exited.")
    sys.exit(0)

def hook():
    QQ_PID = None
    for pid in psutil.pids():
        p = psutil.Process(pid)
        if p.name() == 'QQ.exe':
            if len(p.cmdline()) == 1 or p.cmdline()[1] == '--relaunch':
                QQ_PID = pid
                print(pid, len(p.cmdline()), f'\n\t\t\t{p.cmdline()}')
                del p
                break

    if QQ_PID is None:
        print("QQ not launched. exit.")
        sys.exit(1)
    print("QQ pid is:", QQ_PID)
    print()

    session = frida.get_local_device().attach(QQ_PID)
    script = session.create_script(hook_script)


    script.on("message", on_message)
    script.on("destroyed", on_destroyed)
    script.load()

    print("hooked.")

    sys.stdin.read()

if __name__ == '__main__':
    hook()