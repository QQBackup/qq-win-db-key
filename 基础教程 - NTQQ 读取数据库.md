阅读本文前，您应当已经通过其他方法，获取到了数据库的已解密文件。如果没有，请参考：[基础教程 - NTQQ 解密数据库](基础教程%20-%20NTQQ%20解密数据库.md)。

以下以`nt_msg.db`代指已解密的数据库文件。

目前已知消息格式为`protobuf`，相关解密代码可以参考[提取QQ NT数据库 group_msg_table 中的纯文本](https://github.com/QQBackup/ntdb-plaintext-extracter)、[这份 Python 代码](https://github.com/QQBackup/QQ-History-Backup/issues/9#issuecomment-1929105881)与[这份 protobuf 定义](https://github.com/QQBackup/qq-win-db-key/issues/38#issuecomment-2294619828)，完整实现暂无，欢迎贡献。
