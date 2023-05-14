# Android (Termux ver)

首先，安装 Termux，换源并执行`pkg up`、`termux-setup-storage`

然后依次执行以下命令：

安装基础依赖：

```shell
pkg in python wget tsu
pkg in frida frida-python
```

接着，手动下载主版本相同的`frida-server`，解压到`/data/local/tmp`下，并重命名为`fridas`；

赋予`fridas`可执行权限后，新开一个终端以`root`权限运行`fridas`

下载 hook 脚本：

```shell
wget https://github.com/Young-Lord/qq-win-db-key/raw/master/android_hook.py
```

运行：

```shell
tsu
python android_hook.py
```

QQ 此时应当自动打开，若没有，请检查：

- 是否以`root`权限运行`frida`及`python`
- 是否已经关闭`Magisk Hide`与`Shamiko`，并且重启手机
- `frida-server`与 Termux 中的`frida`版本号第一个点号前的数字是否相同

接下来，可以确认命令行是否有输出。

# PC (adb)

你也可以使用`adb`来避免在手机端配置`Termux`。具体过程略。
