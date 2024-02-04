## 获取聊天记录文件

> 注：以下提到的“电脑”泛指一切可以运行此程序的环境，如安卓手机上的 Termux 也属于此列
> 注：以下内容假设您使用的是 QQ 而非 TIM，如果您在使用 TIM，请将`com.tencent.mobileqq`改为`com.tencent.tim`，将`MobileQQ`改为`Tim`

如果手机已获得 root 权限，聊天记录可在以下路径找到。

```plain
/data/data/com.tencent.mobileqq/
```

我们需要的文件只有`databases/<QQ号>.db`，`databases/slowtable_<QQ号>.db`，`files/kc`，因此您可以将整个文件夹压缩后传输到电脑上，亦或将这三个文件单独放在同一个目录中传输。本程序会自动识别这两种不同的目录结构。

如果没有 root 权限，可以通过手机自带的备份工具备份整个 QQ，拷贝备份文件到电脑，解压找到 `com.tencent.mobileqq`。该方法可行性及具体操作各个系统有差异，请自行在互联网查询。

具体方法可以参见

> 怎样导出手机中的QQ聊天记录？ - 益新软件的回答 - 知乎
> <https://www.zhihu.com/question/28574047/answer/964813560>

如果同时需要在聊天记录中显示图片，拷贝手机中 `/sdcard/Android/data/com.tencent.mobileqq/Tencent/MobileQQ/chatpic/chatimg` 至 `GUI.exe` 同一文件夹中或者拷贝过来的`com.tencent.mobileqq`目录下。

（QQ）如果同时需要在聊天记录中显示语音，拷贝手机中 `/sdcard/Android/data/com.tencent.mobileqq/Tencent/MobileQQ/<QQ号>/ptt` 至 `GUI.exe` 同一文件夹中或者拷贝过来的`com.tencent.mobileqq`目录下。

（TIM）如果同时需要在聊天记录中显示语音，拷贝手机中 `/sdcard/Android/data/com.tencent.tim/Tencent/Tim/ptt/<QQ号>` 至 `GUI.exe` 同一文件夹中或者拷贝过来的`com.tencent.mobileqq`目录下，并重命名为`ptt`。

其他可能需要提取的数据文件可以参照[此处](https://github.com/lqzhgood/Shmily-Get-MobileQQ-Andriod?tab=readme-ov-file)。

## 解密、转换

建议使用以下项目（本列表可能随时间更新）：

- [lqzhgood/Shmily-Get-MobileQQ-Andriod](https://github.com/lqzhgood/Shmily-Get-MobileQQ-Andriod) ![GitHub last commit](https://img.shields.io/github/last-commit/lqzhgood/Shmily-Get-MobileQQ-Andriod/main)
- [Hakuuyosei/QQHistoryExport](https://github.com/Hakuuyosei/QQHistoryExport) ![GitHub last commit](https://img.shields.io/github/last-commit/Hakuuyosei/QQHistoryExport/master)
- [ZhangJun2017/QQChatHistoryExporter](https://github.com/ZhangJun2017/QQChatHistoryExporter) ![GitHub last commit](https://img.shields.io/github/last-commit/ZhangJun2017/QQChatHistoryExporter/master)
- [QQBackup/QQ-History-Backup](https://github.com/QQBackup/QQ-History-Backup) ![GitHub last commit](https://img.shields.io/github/last-commit/QQBackup/QQ-History-Backup/master)
- [QQ-G 手机QQ本地聊天记录查看器 - 吾爱破解](https://www.52pojie.cn/thread-1227585-1-1.html) 2020/7/29 更新
