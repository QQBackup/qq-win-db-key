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
const open_function = single_function("##558BEC6A006A06FF750CFF7508E8E0130200")
const name_function = single_function("55 8B EC FF 75 0C FF 75 08 E8 B8 D1 02 00 59 59 85")
const rekey_function = single_function("##558BEC837D1010740D682F020000E8")
const close_function = single_function("##55 8B EC 56 8B  75 08 85 F6 74 6D 56 E87C 3E 01 00")
const exec_function = single_function("##558BEC8B45088B40505DC3")
// send(key_function)
var open_function_caller = new NativeFunction(open_function, 'int', ['pointer', 'pointer']);
var name_function_caller = new NativeFunction(name_function, 'pointer', ['pointer', 'pointer']);
var rekey_function_caller = new NativeFunction(rekey_function, 'int', ['pointer', 'pointer', 'int']);
var key_function_caller = new NativeFunction(key_function, 'int', ['pointer', 'pointer', 'int']);
var close_function_caller = new NativeFunction(close_function, 'int', ['pointer', 'int']);
var exec_function_caller = new NativeFunction(exec_function, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
var TARGET_KEY_LENGTH = 16;
var key_length = 0;
var dbName;
const new_database_handle = Memory.alloc(128)
var new_database_handle_point_to;
const new_database_name = Memory.alloc(2048)
var empty_password = Memory.alloc(TARGET_KEY_LENGTH)
var original_password = Memory.alloc(TARGET_KEY_LENGTH)
empty_password.writeByteArray(Array(TARGET_KEY_LENGTH).fill(0))
const no_sync = "PRAGMA synchronous=ON"
const no_sync_address = Memory.allocUtf8String(no_sync)
const TEST_PWD_SQL = Memory.allocUtf8String("SELECT count(*) FROM sqlite_master;")

var store_args_1, store_args_2, target_db;
var should_copy = false;
var calling_key = false;
var should_show = false;
var file_path = null;

function is_db_ok(){
    return !exec_function_caller(target_db, TEST_PWD_SQL, NULL, NULL, NULL);
}

Interceptor.attach(key_function, {
    onEnter: function (args, state) {
        if(calling_key){ return; }
        should_copy = false;
        should_show = false;
        console.log("[+] key found:");
        dbName = name_function_caller(args[0], NULL).readUtf8String();
        if (dbName.replaceAll('/', '\\\\').split('\\\\').pop().toLowerCase() == 'Msg3.0.db'.toLowerCase() || false) {
            should_show = true;
            target_db = args[0];
            // disable memory cache
            //console.log("¦- db: " + args[0]);
            key_length = args[2].toInt32()
            console.log("¦- nKey: " + key_length);
            //console.log("¦- pkey: " + args[1]);
            console.log("¦- *pkey: " + buf2hex(args[1].readByteArray(key_length)));
            console.log("¦- dbName: " + name_function_caller(args[0], NULL).readUtf8String());
            //console.log("¦- *pkey: " + buf2hex(Memory.readByteArray(new UInt64(args[1]), key_length)));
            if(key_length == TARGET_KEY_LENGTH){
                Memory.copy(original_password, args[1], key_length)
                should_copy = true;
                send("!!MSG3.0: " + dbName)
                recv('file_path', function(msg){file_path = msg['path']}).wait();
                send("open new db: " + open_function_caller(Memory.allocUtf8String(file_path), new_database_handle))
                new_database_handle_point_to = new_database_handle.readPointer()
                send("decrypt new db: " + key_function_caller(new_database_handle_point_to, original_password, key_length))
                send("rekey new db: " + rekey_function_caller(new_database_handle_point_to, empty_password, key_length))
                send("close new db: " + close_function_caller(new_database_handle_point_to, 0))
                send("!!POS3.0: " + file_path)
            }
        }
    },
    
    onLeave: function (retval, state) {
        if(calling_key){ return; }
        if(!should_show){ return; }
        console.log("¦- sqlite3_key return: " + retval);
        console.log("¦- is_db_ok: " + is_db_ok());
        if (should_copy) {
//            exec_function_caller(target_db, no_sync_address, NULL, NULL, NULL);
//            console.log("rekey to NULL: " + rekey_function_caller(target_db, empty_password, key_length))
//            console.log("¦- is_db_ok: " + is_db_ok());
            // console.log(close_function_caller(target_db, 0))
//            send("!!MSG3.0: " + dbName)
//            recv('file_path', function(msg){file_path = msg['path']}).wait();
//            console.log("rekey to orig: " + rekey_function_caller(target_db, original_password, key_length))
//            console.log("¦- is_db_ok: " + is_db_ok());
//            calling_key = true;
//            // console.log(key_function_caller(target_db, original_password, key_length))
//            calling_key = false;
        }
    }

});



var rekey_show_result = false;
Interceptor.attach(rekey_function, {
    onEnter: function (args, state) {
        console.log("[*] rekey:");
        dbName = name_function_caller(args[0], NULL).readUtf8String();
        rekey_show_result = false
        if (dbName.replaceAll('/', '\\\\').split('\\\\').pop().toLowerCase() == 'Msg3.0.db'.toLowerCase() || false) {
            rekey_show_result = true;
            //console.log("¦- db: " + args[0]);
            key_length = args[2].toInt32()
            console.log("¦- nKey: " + key_length);
            //console.log("¦- pkey: " + args[1]);
            console.log("¦- *pkey: " + buf2hex(args[1].readByteArray(key_length)));
            console.log("¦- dbName: " + name_function_caller(args[0], NULL).readUtf8String());
            //console.log("¦- *pkey: " + buf2hex(Memory.readByteArray(new UInt64(args[1]), key_length)));
        }
    },
    
    onLeave: function (retval, state) {
        if(!rekey_show_result){ return; }
        console.log("¦- sqlite3_rekey return: " + retval);
    }

});
"""

session = frida.get_local_device().attach(QQ_PID)
script = session.create_script(hook_script)
message_seq = 0
new_filename = ""


def on_message(message, data):
    global message_seq, new_filename
    if message["type"] == "send":
        if message["payload"] == "!!exit":
            exit(3)
        if message["payload"].startswith("!!MSG3.0: "):
            filename = message["payload"][10:]
            new_filename = (
                filename.split("\\")[-1]
                + "_"
                + str(message_seq)
                + "_"
                + str(time.time()).split(".")[0]
                + ".db"
            )
            message_seq += 1
            print("Copying decrypted file:", filename, "to", new_filename)
            shutil.copyfile(filename, new_filename)
            script.post({"type": "file_path", "path": os.path.abspath(new_filename)})
        elif message["payload"].startswith("!!POS3.0: "):
            file1 = open(new_filename, "rb")
            extra_flag = False
            # detect extra sqlite header "SQLite header 3"
            if file1.read(15) == b"SQLite header 3":
                file1.seek(1024)
                if file1.read(15) == b"SQLite format 3":
                    file1.seek(1024)
                    extra_flag = True
                    print("NEW PLAIN TEXT DB detected!")
            if not extra_flag:
                file1.seek(0)
                print("hmm db seems still encrypted... anything wrong?")
            file1.close()
            # remove extra 1024 bytes header of a huge file
            if extra_flag:
                file1 = open(new_filename, "rb")
                file2 = open(new_filename + ".tmp", "wb")
                file1.seek(1024)
                shutil.copyfileobj(file1, file2)
                file1.close()
                file2.close()
                os.remove(new_filename)
                os.rename(new_filename + ".tmp", new_filename)
            print("Done. File Path:")
            print(os.path.abspath(new_filename))
        else:
            print(message["payload"])
    elif message["type"] == "error":
        print(message["stack"])


def on_destroyed():
    print("process exited.")
    os._exit(0)


script.on("message", on_message)
script.on("destroyed", on_destroyed)
script.load()
print("hooked.")
sys.stdin.read()
