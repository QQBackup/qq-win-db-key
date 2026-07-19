# qq-win-db-key

QQ Windows/NTQQ 相关数据库密钥提取脚本与辅助源码。

平台教程、数据库解密与读取说明统一维护在 [QQDecrypt 文档库](https://github.com/QQBackup/QQDecrypt)，在线文档见 [qqbackup.github.io/QQDecrypt](https://qqbackup.github.io/QQDecrypt/)。本仓库不再存放教程正文和教程图片。

## 内容范围

- 根目录：各平台密钥提取、数据库导出和重加密脚本。
- `scripts/`：可复用的辅助脚本和研究配套代码。

脚本通常需要根据 QQ 版本、系统环境和本地安装情况调整。使用前请先审查代码并备份数据。

## 警告⚠

尽管部分脚本已经过实验验证可用，本仓库中的工具**可能**破坏聊天记录或导致封号。使用前请自行审查代码、评估风险，并做好以下准备：

- 先使用更保险的方式导出聊天记录，例如 PCQQ（Windows）自带的“导出消息记录（`mht` 格式）”。
- 备份原始数据，例如使用 Android 系统备份功能或进行电脑全盘备份。
- 优先在不常用设备或虚拟机中操作。
- 尽可能选择不注入 QQ 进程、不修改 QQ 安装包的方式。

## 关于

本仓库负责提供获取 PCQQ / QQ NT 等软件数据库密钥、导出数据库和辅助处理的代码。面向用户的分平台操作教程、通用解密流程和数据库解析说明请前往 [QQDecrypt 文档库](https://github.com/QQBackup/QQDecrypt)。

本项目并非面向纯小白的完整教程，而是在假设使用者具备一定逆向、动态调试和脚本修改能力的前提下提供参考实现。脚本可能需要根据 QQ 版本、系统环境和本地安装情况调整。

## 寻求合作者

欢迎能够实现数据解析算法、适配其他平台或改进脚本的贡献者参与本项目以及 [QQ-History-Backup](https://github.com/QQBackup/QQ-History-Backup/tree/dev) 的开发。欢迎直接提交 PR 或 issue；教程内容请在 [QQDecrypt](https://github.com/QQBackup/QQDecrypt) 中维护。

## 声明

本项目仅供学习交流使用，严禁用于任何违反中国大陆法律法规、您所在地区法律法规或 [QQ 软件许可及服务协议](https://rule.tencent.com/rule/preview/46a15f24-e42c-4cb6-a308-2347139b1201) 的行为。开发者不承担任何相关行为导致的直接或间接责任。

本项目不对脚本运行结果的完整性、准确性或可用性作任何担保。生成内容不可用于法律取证，也不应当用于学习交流以外的用途。

本项目遵循 `LICENSE` 中的开源协议；部分文件可能附带独立授权声明，请以文件内说明为准。若项目后续无人维护，可以创建新仓库接手，但请保留原作者信息并在本仓库 issue 中说明。

## 相关项目

- [QQDecrypt](https://github.com/QQBackup/QQDecrypt)：教程与数据库解析文档站。
- [QQ-History-Backup](https://github.com/QQBackup/QQ-History-Backup)：聊天记录备份项目。
- [qq-chat-exporter](https://github.com/shuakami/qq-chat-exporter/)：基于 NapCatQQ 的聊天记录导出工具。

## 致谢

- [看雪](https://bbs.kanxue.com/search-qq-1-144.htm)：保留了二十年来的帖子和附件，大大便利了旧版应用分析。
- 感谢 [Young-Lord](https://github.com/Young-Lord) 及所有贡献代码、教程和测试反馈的贡献者。
