## 找密钥

两种方法，其中搜索内存的方法可能更简单，但效率低并且不一定稳定。Frida hook 需要每次去找相关函数地址、参数列表，并适当修改。

Frida hook：可以直接使用 [msojocs/nt-hook](https://github.com/msojocs/nt-hook) 得到数据库密钥，可能需要微调代码。

搜索内存，并穷举可能的密码字符串：参考[此 gist](https://gist.github.com/bczhc/c0f29920d4e9d0cc6d2c49f7f2fb3a78)。

## 解密

找到密钥之后，按照其他平台教程中列出方式解密即可。此处不再赘述。
