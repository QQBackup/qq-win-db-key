// frida -U -f com.tencent.mobileqq -l final.js
// https://blog.yllhwa.com/2023/09/29/Android%20QQ%20NT%E7%89%88%E6%95%B0%E6%8D%AE%E5%BA%93%E8%A7%A3%E5%AF%86/
const DATABASE = "nt_msg.db";
const module_name = "libkernel.so";

// FOR LOG
let SQLITE3_EXEC_CALLBACK_LOG = true;
let index1 = 0;
let xCallback = new NativeCallback(
  (para, nColumn, colValue, colName) => {
    if (!SQLITE3_EXEC_CALLBACK_LOG) {
      return 0;
    }
    console.log();
    console.log(
      "------------------------" + index1++ + "------------------------"
    );
    for (let index = 0; index < nColumn; index++) {
      let c_name = colName
        .add(index * 8)
        .readPointer()
        .readUtf8String();
      let c_value = "";
      try {
        c_value =
          colValue
            .add(index * 8)
            .readPointer()
            .readUtf8String() ?? "";
      } catch {}
      console.log(c_name, "\t", c_value);
    }
    return 0;
  },
  "int",
  ["pointer", "int", "pointer", "pointer"]
);

// CODE BELOW
var kernel_so = null;
function single_function(pattern) {
  pattern = pattern
    .replaceAll("##", "")
    .replaceAll(" ", "")
    .toLowerCase()
    .replace(/\\s/g, "")
    .replace(/(.{2})/g, "$1 ");
  var akey_function_list = Memory.scanSync(
    kernel_so.base,
    kernel_so.size,
    pattern
  );
  if (akey_function_list.length > 1) {
    console.log("pattern FOUND MULTI!!");
    console.log(pattern);
    console.log(akey_function_list);
    throw Error("pattern FOUND MULTI!!");
  }
  if (akey_function_list.length == 0) {
    console.log("pattern NOT FOUND!!");
    console.log(pattern);
    throw Error("pattern NOT FOUND!!");
  }
  return akey_function_list[0]["address"];
}

let get_filename_from_sqlite3_handle = function (sqlite3_db) {
  // full of magic number
  let zFilename = "";
  try {
    let db_pointer = sqlite3_db.add(0x8 * 5).readPointer();
    let pBt = db_pointer.add(0x8).readPointer();
    let pBt2 = pBt.add(0x8).readPointer();
    let pPager = pBt2.add(0x0).readPointer();
    zFilename = pPager.add(208).readPointer().readCString();
  } catch (e) {}
  return zFilename;
};

let hook = function () {
  var process_Obj_Module_Arr = Process.enumerateModules();
  for (var i = 0; i < process_Obj_Module_Arr.length; i++) {
    if (process_Obj_Module_Arr[i].path.indexOf(module_name) !== -1) {
      kernel_so = process_Obj_Module_Arr[i];
    }
  }
  if (kernel_so === null) {
    console.log(module_name + " not loaded. exit.");
    throw Error(".so not loaded");
  }

  // sqlite3_exec -> sub_1CFB9C0
  // let sqlite3_exec_addr = base_addr.add(0x1cfb9c0);
  let sqlite3_exec_addr = single_function(
    "FF 43 02 D1  FD 7B 03 A9 FC 6F 04 A9  FA 67 05 A9 F8 5F 06 A9    F6 57 07 A9 F4 4F 08 A9  FD C3 00 91 54 D0 3B D5    88 16 40 F9 F8 03 04 AA  F5 03 03 AA F6 03 02 AA"
  ); // 貌似是稳定的，先这样写
  console.log("sqlite3_exec_addr: " + sqlite3_exec_addr);

  let sqlite3_exec = new NativeFunction(sqlite3_exec_addr, "int", [
    "pointer",
    "pointer",
    "pointer",
    "int",
    "int",
  ]);

  let target_db_handle = null;
  let js_sqlite3_exec = function (sql) {
    if (target_db_handle === null) {
      return -1;
    }
    let sql_pointer = Memory.allocUtf8String(sql);
    return sqlite3_exec(target_db_handle, sql_pointer, xCallback, 0, 0);
  };

  // ATTACH BELOW
  Interceptor.attach(sqlite3_exec_addr, {
    onEnter: function (args) {
      // sqlite3*,const char*,sqlite3_callback,void*,char**
      let sqlite3_db = ptr(args[0]);
      let sql = Memory.readCString(args[1]);
      let callback_addr = ptr(args[2]);
      let callback_arg = ptr(args[3]);
      let errmsg = ptr(args[4]);
      let database_name = get_filename_from_sqlite3_handle(sqlite3_db);
      if (
        database_name.slice(database_name.lastIndexOf("/") + 1) === DATABASE
      ) {
        console.log("sqlite3_db: " + sqlite3_db);
        console.log("sql: " + sql);
        target_db_handle = sqlite3_db;
      }
    },
  });
  setTimeout(function () {
    let EXPORT_FILE_PATH = "/storage/emulated/0/Download/plaintext.db";
    // 不建议更改导出路径
    console.log("Start exporting database to " + EXPORT_FILE_PATH);
    let ret = js_sqlite3_exec(
      `ATTACH DATABASE '` +
        EXPORT_FILE_PATH +
        `' AS plaintext KEY '';SELECT sqlcipher_export('plaintext');DETACH DATABASE plaintext;`
    );
    console.log("Export end.");
    console.log("js_sqlite3_exec ret: " + ret);
  }, 4000); // hook 后 导出前 等待4秒
};

var hasHooked = false;
console.log("Script loaded. Waiting for " + module_name + " to load...");
const dlopen_process = {
  onEnter: function (args) {
    this.path = Memory.readUtf8String(args[0]);
    if (0) send("Loading " + this.path);
  },
  onLeave: function (retval) {
    if (this.path.indexOf(module_name) !== -1 && !hasHooked) {
      hasHooked = true;
      if (1) send("Hooked!!");
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
