/*
 * QQNT DB-key derivation forensics (Linux) - Frida hook script
 *
 * Goal: capture runtime buffers that bridge:
 *   MSF encrypt_key response (meta/key) -> key_mgr SetKeyPair/InitDbHeader -> DB ext header field2
 *
 * Usage examples:
 *   frida -n qq --runtime=v8 -l frida-tools/qqnt-dbkey-hook.js
 *   frida -n qq --runtime=v8 -l frida-tools/qqnt-dbkey-hook.js --no-pause
 *
 * Notes:
 * - Offsets are wrapper.node *image offsets* (IDA shows imagebase 0x0 in your session).
 * - If your wrapper.node base differs, Frida adds module base automatically.
 */
/* eslint-disable no-undef */

'use strict';

const CFG = {
  moduleName: 'wrapper.node',

  // ---- KeyMgr / DB header writing side (from your IDA labels) ----
  // key_mgr.cc
  off_InitDbHeader: 0x4954000, // sub_4954000
  off_SetExtHeader: 0x4954350, // sub_4954350
  off_SetPsKey: 0x4953660, // sub_4953660
  off_SetKeyPair: 0x49532C0, // sub_49532C0

  // ---- MSF encrypt_key callback side (from your IDA labels) ----
  // desktop_qq_wrapper_session.cc
  off_RequestEncryptKey_cb: 0x243E650, // sub_243E650
  off_RequestDecryptKey_cb: 0x243EFF0, // sub_243EFF0

  // ---- RequestDBKey / MSF request encoding side ----
  off_requestDBKey: 0x2430160, // sub_2430160 (NTWrapperSession::requestDBKey)
  off_EncodeRequestDecryptKey: 0x2DFA1C0, // sub_2DFA1C0 (msf_service.cc request encode helper)
  off_RequestDecryptKey: 0x2DDE920, // sub_2DDE920 (msf_service.cc RequestDecryptKey)
  off_BuildOidbReq: 0x2DDD7F0, // sub_2DDD7F0 (build oidb request body)

  // ---- MSF session init / security sign (72-byte blob source) ----
  off_SessionInit: 0x2DD6FA0, // sub_2DD6FA0 (msf_service.cc SessionInit)
  off_MsfSecuritySignInit: 0x2DD1900, // sub_2DD1900 (MSFSecuritySignCallback::Init)
  off_initComponents: 0x24295A0, // sub_24295A0 -> sub_242FCE0 -> SessionInit
  off_HexDecodeSmallString: 0x7A02C90, // sub_7A02C90 hex ASCII -> bytes (SessionInit sign path)
  off_UpdateConfig: 0x48B0FE0, // session_base.cpp UpdateConfig -> fills session config incl. a2_key
  off_SecurityPersistentGet: 0x2DD20D0, // MSFSecuritySignCallback::SecurityPersistentGetValue (nt_mmkv_o3)
  off_MSFSign: 0x2DD24A0, // MSFSecuritySignCallback::MSFSign

  // How much data to print at most (bytes)
  maxDump: 256,
};

function now() {
  return new Date().toISOString();
}

function log(...args) {
  // eslint-disable-next-line no-console
  console.log(`[${now()}]`, ...args);
}

function hexDump(ptrValue, len, label) {
  if (ptrValue.isNull() || len <= 0) {
    log(`${label}: <null/empty>`);
    return;
  }
  const n = Math.min(len, CFG.maxDump);
  const buf = ptrValue.readByteArray(n);
  log(`${label}: ptr=${ptrValue} len=${len} dump_len=${n}`);
  log(hexdump(buf, { offset: 0, length: n, header: true, ansi: false }));
}

/**
 * QQNT "small-string" layout observed in decomp:
 *   b0 = *(uint8*)s
 *   if (b0 & 1) heap:
 *     len = *(uint64*)(s+8)
 *     data = *(uint64*)(s+16)
 *   else inline:
 *     len = b0 >> 1
 *     data = s+1
 */
function readNtSmallString(sPtr) {
  if (sPtr.isNull()) return { ok: false, reason: 'null' };
  const b0 = sPtr.readU8();
  if ((b0 & 1) === 1) {
    const len = Number(sPtr.add(8).readU64());
    const data = sPtr.add(16).readPointer();
    return { ok: true, heap: true, len, data };
  }
  const len = b0 >>> 1;
  const data = sPtr.add(1);
  return { ok: true, heap: false, len, data };
}

/**
 * "ptr-range" layout observed in decomp:
 *   begin = *(void**)p
 *   end   = *(void**)(p+8)
 *   len = end - begin
 */
function readPtrRange(pPtr) {
  if (pPtr.isNull()) return { ok: false, reason: 'null' };
  const begin = pPtr.readPointer();
  const end = pPtr.add(Process.pointerSize).readPointer();
  const len = end.sub(begin).toInt32();
  return { ok: true, begin, end, len };
}

function safeCString(ptrValue, maxLen = 256) {
  try {
    return ptrValue.readCString(maxLen);
  } catch (_) {
    return null;
  }
}

function safeUtf8(ptrValue, maxLen = 128) {
  if (!ptrValue || ptrValue.isNull()) return null;
  try {
    return ptrValue.readUtf8String(maxLen);
  } catch (_) {
    return safeCString(ptrValue, maxLen);
  }
}

function readNtSmallStringAt(basePtr, off) {
  return readNtSmallString(basePtr.add(off));
}

function dumpSmallStringMaybe(label, sPtr) {
  const s = readNtSmallString(sPtr);
  if (!s.ok) {
    log(`${label}: <read failed: ${s.reason}> ptr=${sPtr}`);
    return;
  }
  const maybeAscii = safeCString(s.data, Math.min(s.len + 1, 512));
  log(`${label}: len=${s.len} heap=${s.heap} ascii=${JSON.stringify(maybeAscii)}`);
  hexDump(s.data, s.len, `${label}_raw`);
}

let g_watchEnabled = false;
function watchWritesOnce(label, basePtr, size) {
  if (g_watchEnabled) return;
  try {
    g_watchEnabled = true;
    log(`[watch] enabling MemoryAccessMonitor for ${label} base=${basePtr} size=0x${size.toString(16)}`);
    MemoryAccessMonitor.enable(
      { base: basePtr, size },
      {
        onAccess(details) {
          // details: { operation, from, address, rangeIndex, pageIndex, pagesCompleted }
          const from = ptr(details.from);
          const mod = Process.findModuleByAddress(from);
          const modStr = mod ? `${mod.name}+0x${from.sub(mod.base).toString(16)}` : '<no-module>';
          const sym = DebugSymbol.fromAddress(from);
          log(
            `[watch] ${label} ${details.operation} from=${from} (${modStr}) sym=${sym} address=${details.address} rangeIndex=${details.rangeIndex}`
          );
          // Only stop on writes; reads are too common/noisy.
          if (details.operation === 'write') {
            try {
              MemoryAccessMonitor.disable();
              log(`[watch] disabled (write hit)`);
            } catch (_) {
              // ignore
            }
          }
        },
      }
    );
  } catch (e) {
    log(`[watch] failed to enable: ${e.stack || e}`);
  }
}

function safeReadNtSmallStringAt(basePtr, off) {
  try {
    return readNtSmallStringAt(basePtr, off);
  } catch (e) {
    return { ok: false, reason: `exception: ${e}` };
  }
}

function hookAtOffset(name, off, onEnter, onLeave) {
  const mod = Process.findModuleByName(CFG.moduleName) || (() => {
    try {
      return Process.getModuleByName(CFG.moduleName);
    } catch (_) {
      return null;
    }
  })();
  if (!mod) throw new Error(`Module not loaded: ${CFG.moduleName}`);
  const base = mod.base;
  const target = base.add(ptr(off));
  log(`Hook ${name} @ ${target} (base=${base} off=0x${off.toString(16)})`);
  Interceptor.attach(target, {
    onEnter(args) {
      this.__name = name;
      this.__target = target;
      try {
        onEnter?.call(this, args);
      } catch (e) {
        log(`[${name}] onEnter error: ${e.stack || e}`);
      }
    },
    onLeave(retval) {
      try {
        onLeave?.call(this, retval);
      } catch (e) {
        log(`[${name}] onLeave error: ${e.stack || e}`);
      }
    },
  });
}

function main() {
  const mod = Process.findModuleByName(CFG.moduleName) || (() => {
    try {
      return Process.getModuleByName(CFG.moduleName);
    } catch (_) {
      return null;
    }
  })();
  if (!mod) {
    log(`Waiting for module ${CFG.moduleName}...`);
    const timer = setInterval(() => {
      const m = Process.findModuleByName(CFG.moduleName);
      if (m) {
        clearInterval(timer);
        main();
      }
    }, 200);
    return;
  }
  const base = mod.base;
  log(`Module ${CFG.moduleName} loaded @ ${base} size=${mod.size}`);

  // 1) KeyMgr::InitDbHeader(db_path, ps_key_bytes?) - prints ps_key buffer that's about to be written to pb field2
  hookAtOffset('InitDbHeader(sub_4954000)', CFG.off_InitDbHeader, function (args) {
    // signature (decomp): sub_4954000(__int128 a1, unsigned __int64 *a2)
    // a1: likely std::string (db path) passed by value in registers; hard to decode generically from here.
    // a2: ptr-range like {begin,end} holding bytes for pb field2 (often ASCII hex).
    const a2 = args[1];
    const pr = readPtrRange(a2);
    if (pr.ok && pr.len > 0 && pr.len < 0x2000) {
      const maybeStr = safeCString(pr.begin, Math.min(pr.len + 1, 256));
      log(`[InitDbHeader] field2_buf len=${pr.len} begin=${pr.begin} maybe_ascii=${JSON.stringify(maybeStr)}`);
      hexDump(pr.begin, pr.len, '[InitDbHeader] field2_raw');
    } else {
      log(`[InitDbHeader] a2 not ptr-range? a2=${a2} pr=${JSON.stringify(pr)}`);
    }
  });

  // 2) KeyMgr::SetExtHeader(path,len, pbObj?) - captures magic/len/pb bytes being written (best-effort)
  hookAtOffset('SetExtHeader(sub_4954350)', CFG.off_SetExtHeader, function (args) {
    // signature from call sites: sub_4954350(path_ptr, path_len, config_node_ptr)
    const pathPtr = args[0];
    const pathLen = args[1].toInt32();
    const path = safeCString(pathPtr, Math.min(pathLen + 1, 512));
    log(`[SetExtHeader] pathLen=${pathLen} path=${JSON.stringify(path)} pathPtr=${pathPtr} cfg=${args[2]}`);
  });

  // 3) RequestEncryptKey callback - prints meta + key buffers that come back from MSF
  hookAtOffset('RequestEncryptKey_cb(sub_243E650)', CFG.off_RequestEncryptKey_cb, function (args) {
    // decomp: sub_243E650(a1, a2(result*), a3(metaSmallString*), a4(keySmallString*), a5(ptr-range?))
    const resultPtr = args[1];
    const result = resultPtr.isNull() ? null : resultPtr.readU32();
    log(`[ReqEncryptKey.cb] result=${result} a1=${args[0]}`);

    // meta is in a3 "small-string" object
    const metaS = readNtSmallString(args[2]);
    if (metaS.ok) {
      const metaAscii = safeCString(metaS.data, Math.min(metaS.len + 1, 256));
      log(`[ReqEncryptKey.cb] meta len=${metaS.len} heap=${metaS.heap} ascii=${JSON.stringify(metaAscii)}`);
      hexDump(metaS.data, metaS.len, '[ReqEncryptKey.cb] meta_raw');
    } else {
      log(`[ReqEncryptKey.cb] meta read failed: ${metaS.reason}`);
    }

    // key bytes are in a4 "small-string" object (often binary)
    const keyS = readNtSmallString(args[3]);
    if (keyS.ok) {
      log(`[ReqEncryptKey.cb] key len=${keyS.len} heap=${keyS.heap}`);
      hexDump(keyS.data, keyS.len, '[ReqEncryptKey.cb] key_raw');
    } else {
      log(`[ReqEncryptKey.cb] key read failed: ${keyS.reason}`);
    }

    // a5 in decomp looked like ptr-range (n/src swap). Dump first ~64 if sane.
    const a5 = args[4];
    const pr = readPtrRange(a5);
    if (pr.ok && pr.len > 0 && pr.len < 0x4000) {
      const maybe = safeCString(pr.begin, Math.min(pr.len + 1, 128));
      log(`[ReqEncryptKey.cb] a5 ptr-range len=${pr.len} maybe_ascii=${JSON.stringify(maybe)}`);
      hexDump(pr.begin, pr.len, '[ReqEncryptKey.cb] a5_raw');
    }
  });

  // 4) RequestDecryptKey callback - prints meta + key buffers
  hookAtOffset('RequestDecryptKey_cb(sub_243EFF0)', CFG.off_RequestDecryptKey_cb, function (args) {
    const resultPtr = args[1];
    const result = resultPtr.isNull() ? null : resultPtr.readU32();
    log(`[ReqDecryptKey.cb] result=${result} a1=${args[0]}`);

    const metaS = readNtSmallString(args[2]);
    if (metaS.ok) {
      const metaAscii = safeCString(metaS.data, Math.min(metaS.len + 1, 256));
      log(`[ReqDecryptKey.cb] meta len=${metaS.len} heap=${metaS.heap} ascii=${JSON.stringify(metaAscii)}`);
      hexDump(metaS.data, metaS.len, '[ReqDecryptKey.cb] meta_raw');
    }

    // Decomp shows key bytes are in a4 ptr-range, not small-string. We'll try both.
    const pr = readPtrRange(args[3]);
    if (pr.ok && pr.len > 0 && pr.len < 0x4000) {
      log(`[ReqDecryptKey.cb] key(ptr-range) len=${pr.len} begin=${pr.begin}`);
      hexDump(pr.begin, pr.len, '[ReqDecryptKey.cb] key_raw');
    } else {
      const keyS = readNtSmallString(args[3]);
      if (keyS.ok) {
        log(`[ReqDecryptKey.cb] key(small-string) len=${keyS.len} heap=${keyS.heap}`);
        hexDump(keyS.data, keyS.len, '[ReqDecryptKey.cb] key_raw');
      }
    }
  });

  // 5) requestDBKey - captures UID and base DB directory input
  hookAtOffset('requestDBKey(sub_2430160)', CFG.off_requestDBKey, function (args) {
    // decomp: sub_2430160(__int64 a1 /*this*/, __int64 a2 /*req struct*/)
    const sess = args[0];
    const req = args[1];
    // Based on decomp:
    // - uid small-string at req+32
    // - dbDir small-string at req+64
    const uidS = readNtSmallStringAt(req, 32);
    const dirS = readNtSmallStringAt(req, 64);
    const uid = uidS.ok ? safeCString(uidS.data, Math.min(uidS.len + 1, 256)) : null;
    const dbDir = dirS.ok ? safeCString(dirS.data, Math.min(dirS.len + 1, 512)) : null;
    log(`[requestDBKey] sess=${sess} req=${req} uid=${JSON.stringify(uid)} dbDir=${JSON.stringify(dbDir)}`);
  });

  // 6) Encode helper used by RequestDecryptKey - dumps the encrypted blob being wrapped into MSF request
  hookAtOffset('EncodeReqDecryptKey(sub_2DFA1C0)', CFG.off_EncodeRequestDecryptKey, function (args) {
    // signature: sub_2DFA1C0(unsigned __int8 *a1 /*small-string*/, __int64 a2 /*out?*/)
    this.__enc_a2 = args[1];
    const inS = readNtSmallString(args[0]);
    if (inS.ok) {
      const maybeAscii = safeCString(inS.data, Math.min(inS.len + 1, 256));
      log(`[EncodeReqDecryptKey] in len=${inS.len} heap=${inS.heap} maybe_ascii=${JSON.stringify(maybeAscii)}`);
      hexDump(inS.data, inS.len, '[EncodeReqDecryptKey] in_raw');
    } else {
      log(`[EncodeReqDecryptKey] in read failed: ${inS.reason}`);
    }
  }, function (_retval) {
    // Try to interpret a2 as ptr-range after encoding (best-effort)
    const a2 = this.__enc_a2;
    if (!a2 || a2.isNull()) return;
    const pr = readPtrRange(a2);
    if (pr.ok && pr.len > 0 && pr.len < 0x4000) {
      const maybe = safeCString(pr.begin, Math.min(pr.len + 1, 256));
      log(`[EncodeReqDecryptKey] out ptr-range len=${pr.len} begin=${pr.begin} maybe_ascii=${JSON.stringify(maybe)}`);
      hexDump(pr.begin, pr.len, '[EncodeReqDecryptKey] out_raw');
    }
  });

  // 7) RequestDecryptKey (MSF service) - attempts to dump the final request payload and routing info
  hookAtOffset('RequestDecryptKey(sub_2DDE920)', CFG.off_RequestDecryptKey, function (args) {
    // sub_2DDE920(a1 /*msf client?*/, a2 /*small-string input?*/, a3 /*out?*/)
    // From decomp, it builds service name: "OidbSvcTrpcTcp.0x%x_%d" with (3294,2)
    log(`[RequestDecryptKey] a1=${args[0]} a2=${args[1]} a3=${args[2]}`);
    // a2 is passed to sub_2DFA1C0 which expects small-string. Dump it here too.
    dumpSmallStringMaybe('[RequestDecryptKey] enc_hex', args[1]);

    // a3 behaves like an object with function pointers at +16 used to output 16 bytes; keep address for correlation.
    log(`[RequestDecryptKey] out_obj=${args[2]}`);

    // MemoryAccessMonitor on MSFService+0x210 breaks BuildOidbReq reads — blob already captured in SessionInit.
  });

  // 8) Build OIDB request body - dumps the exact bytes that become MSF request payload
  hookAtOffset('BuildOidbReq(sub_2DDD7F0)', CFG.off_BuildOidbReq, function (args) {
    // sub_2DDD7F0(out_vec3ptr, a2, cmd, subcmd, payload_vec, a6)
    // In RequestDecryptKey it's called with cmd=3294 subcmd=2 payload=out_raw (from EncodeReqDecryptKey)
    this.__oidb_out = args[0];
    log(`[BuildOidbReq] out=${args[0]} a2=${args[1]} cmd=${args[2].toInt32()} subcmd=${args[3].toInt32()} payload_vec=${args[4]} a6=${args[5].toInt32()}`);

    // a2 has a small-string at +0x210 (528) that is inserted into nested field (seen as "12 48 <72 bytes>" in out_vec_raw).
    // Dump it as raw bytes (often binary, not UTF-8).
    const a2 = args[1];
    if (a2 && !a2.isNull()) {
      const ss = safeReadNtSmallStringAt(a2, 528);
      if (ss.ok) {
        log(`[BuildOidbReq] a2+0x210 small-string len=${ss.len} heap=${ss.heap} data=${ss.data}`);
        hexDump(ss.data, ss.len, '[BuildOidbReq] a2_0x210_raw');
      } else {
        log(`[BuildOidbReq] a2+0x210 small-string read failed: ${ss.reason}`);
      }
    }

    // Dump payload_vec (a5): it is a {begin,end} style or {ptr,len}? In decomp used as {ptr,?,end} with len = *(a5+8)-*(a5)
    const pr = readPtrRange(args[4]);
    if (pr.ok && pr.len > 0 && pr.len < 0x8000) {
      log(`[BuildOidbReq] payload ptr-range len=${pr.len} begin=${pr.begin}`);
      hexDump(pr.begin, pr.len, '[BuildOidbReq] payload_raw');
    }
  }, function (_retval) {
    // out is a 3-pointer vector: begin/end/cap (std::vector<uint8_t>)
    const out = this.__oidb_out;
    if (!out || out.isNull()) return;
    const begin = out.readPointer();
    const end = out.add(Process.pointerSize).readPointer();
    const len = end.sub(begin).toInt32();
    if (len > 0 && len < 0x20000) {
      log(`[BuildOidbReq] out_vec len=${len} begin=${begin}`);
      hexDump(begin, len, '[BuildOidbReq] out_vec_raw');
    }
  });

  // Optional: mark when SetKeyPair is called (doesn't decode params here yet)
  hookAtOffset('SetKeyPair(sub_49532C0)', CFG.off_SetKeyPair, function (args) {
    log(`[SetKeyPair] this=${args[0]} keypairs=${args[1]}`);
  });

  // 9) SessionInit - copies config+0xF0 (240) -> MSFService+0x210 (528); this is the 72-byte OIDB sign blob
  hookAtOffset('SessionInit(sub_2DD6FA0)', CFG.off_SessionInit, function (args) {
    const msfSvc = args[0];
    const config = args[2];
    log(`[SessionInit] msfSvc=${msfSvc} config=${config}`);
    if (config && !config.isNull()) {
      dumpSmallStringMaybe('[SessionInit] config+0x58 nt_data_dir', config.add(88));
      dumpSmallStringMaybe('[SessionInit] config+0xF0 a2_key_hex', config.add(240));
      dumpSmallStringMaybe('[SessionInit] config+0x108 sec_material_hex', config.add(264));
      dumpSmallStringMaybe('[SessionInit] config+0x120 qua_hex', config.add(288));
    }
    this.__msfSvc = msfSvc;
  }, function (_retval) {
    const msfSvc = this.__msfSvc;
    if (!msfSvc || msfSvc.isNull()) return;
    dumpSmallStringMaybe('[SessionInit] MSFService+0x210 after', msfSvc.add(528));
  });

  // 10) MSFSecuritySignCallback::Init - reads/writes nt_mmkv_o3, uses security_data dir
  hookAtOffset('MsfSecuritySignInit(sub_2DD1900)', CFG.off_MsfSecuritySignInit, function (args) {
    const cb = args[0];
    const initCtx = args[1];
    const dataDir = args[2];
    log(`[MsfSecuritySignInit] cb=${cb} initCtx=${initCtx} dataDir=${dataDir}`);
    if (initCtx && !initCtx.isNull()) {
      dumpSmallStringMaybe('[MsfSecuritySignInit] initCtx+0x48 uin', initCtx.add(72));
    }
    if (dataDir && !dataDir.isNull()) {
      dumpSmallStringMaybe('[MsfSecuritySignInit] dataDir', dataDir);
    }
  });

  // 11) initComponents - triggers sub_242FCE0(session, session+344) which calls SessionInit
  hookAtOffset('initComponents(sub_24295A0)', CFG.off_initComponents, function (args) {
    const sess = args[0];
    log(`[initComponents] session=${sess} config@session+344`);
    if (sess && !sess.isNull()) {
      dumpSmallStringMaybe('[initComponents] config+0xF0 a2_key_hex', sess.add(344 + 240));
    }
  });

  // 12) Hex decode: sub_7A02C90(out_ss, raw_hex_ptr, hex_ascii_byte_len)
  hookAtOffset('HexDecode(sub_7A02C90)', CFG.off_HexDecodeSmallString, function (args) {
    this.__hex_out = args[0];
    const inPtr = args[1];
    const inLen = Number(args[2]);
    // Filter bogus calls: real path uses even len 2..352 (144 hex chars for a2_key)
    if (!inPtr || inPtr.isNull() || inLen < 2 || inLen > 352 || (inLen % 2) !== 0) {
      this.__hex_skip = true;
      return;
    }
    this.__hex_skip = false;
    this.__hex_in_len = inLen;
    log(`[HexDecode] in_ascii_bytes=${inLen} out_bytes=${inLen / 2}`);
    hexDump(inPtr, inLen, '[HexDecode] in_hex_ascii');
  }, function (_retval) {
    if (this.__hex_skip) return;
    const out = this.__hex_out;
    if (!out || out.isNull()) return;
    const s = readNtSmallString(out);
    if (s.ok && s.len > 0 && s.len <= 256) {
      hexDump(s.data, s.len, '[HexDecode] out_bytes');
    }
  });

  // 13) UpdateConfig - login path writes session config (incl. a2_key @ config+0xF0)
  hookAtOffset('UpdateConfig(sub_48B0FE0)', CFG.off_UpdateConfig, function (args) {
    const base = args[0];
    const incoming = args[1];
    log(`[UpdateConfig] base=${base} incoming=${incoming}`);
    if (incoming && !incoming.isNull()) {
      dumpSmallStringMaybe('[UpdateConfig] incoming+0xF0 a2_key_hex', incoming.add(240));
      dumpSmallStringMaybe('[UpdateConfig] incoming+0x108 sec_material', incoming.add(264));
      dumpSmallStringMaybe('[UpdateConfig] incoming+0x120 qua_hex', incoming.add(288));
    }
  });

  // 14) MMKV persistent read (nt_mmkv_o3) - keys feed security sign init
  const mmkvSeen = new Set();
  hookAtOffset('SecurityPersistentGet(sub_2DD20D0)', CFG.off_SecurityPersistentGet, function (args) {
    const key = safeUtf8(args[0], 96);
    if (!key || key.length === 0 || key.length > 96) return;
    this.__mmkv_key = key;
    this.__mmkv_do = true;
  }, function (retval) {
    if (!this.__mmkv_do) return;
    const key = this.__mmkv_key;
    if (mmkvSeen.has(key)) return;
    mmkvSeen.add(key);
    if (retval.isNull()) {
      log(`[SecurityPersistentGet] key=${JSON.stringify(key)} -> null`);
      return;
    }
    log(`[SecurityPersistentGet] key=${JSON.stringify(key)} ptr=${retval}`);
    hexDump(retval, CFG.maxDump, '[SecurityPersistentGet] val_head');
  });

  // 15) MSFSign - filter noisy trpc.o3.report spam
  const msfSignSeen = new Set();
  const msfSignKeep = /OidbSvcTrpcTcp|login|ecdh|EstablishShare|ce6|DecryptKey|EncryptKey/i;
  hookAtOffset('MSFSign(sub_2DD24A0)', CFG.off_MSFSign, function (args) {
    const modS = readNtSmallString(args[1]);
    if (!modS.ok || modS.len <= 0 || modS.len > 128) return;
    const mod = safeUtf8(modS.data, modS.len + 1);
    if (!mod || !msfSignKeep.test(mod)) return;
    if (msfSignSeen.has(mod)) return;
    msfSignSeen.add(mod);
    log(`[MSFSign] module=${JSON.stringify(mod)}`);
  });

  log('Hooks installed.');
}

setImmediate(main);

