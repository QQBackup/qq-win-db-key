1. 1. 定位 `nt_sqlite3_key_v2:`

   此处采用 IDA 演示，您可以替换成您喜欢的任何反编译器

   ![image-20230716124653784](.\img\image-20230716124653784.png)

   定位到字符串 `nt_sqlite3_key_v2: db=%p zDb=%s`

   ![image-20230716124834751](.\img\image-20230716124834751.png)

   查看引用，进入引用的函数

   ![image-20230716124931612](.\img\image-20230716124931612.png)

   找到函数头

   复制特征 Hex 

   QQ 9.9.1.15043 为

   ```
   48 89 5C 24 08 48 89 6C  24 10 48 89 74 24 18 57
   48 83 EC 20 41 8B F9 49  8B F0 4C 8B CA 4C 8B C1
   48 8B EA 48 8B D9 48 8D  15 33 05 A0 00 B9 08 00
   ```

2. Hook 并找到 Key

   根据 https://www.zetetic.net/sqlcipher/sqlcipher-api/#sqlite3_key 指出

   `sqlite3_key_v2` 的签名为

   ```c
   int sqlite3_key_v2(
     sqlite3 *db,                   /* Database to be keyed */
     const char *zDbName,           /* Name of the database */
     const void *pKey, int nKey     /* The key */
   );
   ```

   其中对我们有用的是 `pKey` 和 `nKey`

   作者本人采用 frida hook

   根据 repo 提供的脚本略加修改，很容易得到我们需要的 `pKey` 和 `nKey` 

   PS：有概率你会得到的一个长度为 20 的 key，但那不是我们想要的，可以挂上一个动态调试器来观察 key 对应的具体数据库

3. 删去文件头并打开数据库

   使用二进制编辑器打开 `nt_msg.db` 或 `group_msg_fts.db` 都会发现文件前有长达 1024 个字符的纯文本内容，这不是数据库内容，在复制原数据库后，务必删除

   随后使用你喜欢的工具打开这个数据库，注意 kdf 迭代次数腾讯可能为了性能改为了 4000 次而不是默认的 256000 次。

   ![image-20230716130512061](.\img\image-20230716130512061.png)

   