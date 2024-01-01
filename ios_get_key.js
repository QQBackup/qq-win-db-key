// frida [-U/-R/-H/-D] QQ -l ios_get_key.js

const ModuleName = "QQ";

// QQ(iOS) v9.0.1.620
// SQLCipher v4.5.1
const SQLLiteKeyV2Offset = 0xDA1BFB4;

const sqlLiteKeyV2Addr = Module.findBaseAddress(ModuleName).add(SQLLiteKeyV2Offset);

/**
 * @param {Array<number>} buffer
 * @returns {string}
 */
function buf2hex(buffer) {
    const byteArray = new Uint8Array(buffer);
    const hexParts = [];
    byteArray.forEach(value => {
        const hex = value.toString(16);
        const paddedHex = ('00' + hex).slice(-2);
        hexParts.push(paddedHex);
    })
    return '0x' + hexParts.join(', 0x');
}

/**
 * @param {Array<number>} buffer
 * @returns {string}
 */
function buf2str(buffer) {
    let result = "";
    const byteArray = new Uint8Array(buffer);
    byteArray.forEach(value => {
        result += String.fromCharCode(value);
    })
    return result;
}

/**
 * @param {Object} sqlite3 - Database connection (struct sqlite3)
 * {@link https://github.com/sqlcipher/sqlcipher/blob/2c672e7dd1f3dee4aa1af0b5bf29092db4b10f78/src/sqliteInt.h#L1513-L1655}
 * @returns {string} Name of the database file
 */
function getFilenameFromDB(sqlite3) {
    let result = "";
    try {
        let db = sqlite3.add(0x8 * 5).readPointer();    // All backends (Db *)
        let pBt = db.add(0x8).readPointer();    // The B*Tree structure for this database file (Btree *)
        let pBt2 = pBt.add(0x8).readPointer();  // Sharable content of this btree (BtShared *)
        let pPager = pBt2.add(0x0).readPointer();   // The page cache (Pager *)
        let zFilename = pPager.add(208).readPointer();  // Name of the database file (char *)
        result = zFilename.readCString();
    } catch (e) {}
    return result;
}

/*
    int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey);
 */
Interceptor.attach(sqlLiteKeyV2Addr, {
    /**
     * @param {array} args
     */
    onEnter: function (args) {
        const dbPtr = args[0];
        const zDbPtr = args[1];
        const pKeyPtr = args[2];
        const nKeyPtr = args[3];

        const nKey = nKeyPtr.toInt32();
        const pKeyByteArray = pKeyPtr.readByteArray(nKey)
        const pKey = buf2str(pKeyByteArray)
        const pKeyHex = buf2hex(pKeyByteArray)
        const zDb = zDbPtr.readUtf8String();

        const zFilename = getFilenameFromDB(dbPtr)

        const zFilenameParts = zFilename.split("/")
        const dirName = zFilenameParts[zFilenameParts.length - 3]
        const dbName =  zFilenameParts[zFilenameParts.length - 1]
        if (dirName === "nt_db" || dbName === "nt_msg.db") {
            console.log(`¦- db: ${dbPtr}`);
            console.log(`¦- *zDb: ${zDb}`);
            console.log(`¦- *pkey: ${pKey}`);
            console.log(`¦- *pkey-hex: ${pKeyHex}`);
            console.log(`¦- nKey: ${nKey}`);
            console.log(`¦+`);
            console.log(`¦- zFilename: ${zFilename}`);
            console.log("+------------");
        }
    }
});
