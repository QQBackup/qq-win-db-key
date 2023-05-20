# Android (Termux ver)

首先，安装 Termux，换源并执行`pkg up`、`termux-setup-storage`

然后依次执行以下命令：

安装基础依赖：

```shell
pkg in python wget tsu
pkg in frida frida-python
```

关闭 SELinux：

```shell
su -c setenforce 0
```

接着，手动下载主版本相同的`frida-server`，解压到`/data/local/tmp`下，并重命名为`fri`；

赋予`fri`可执行权限后，新开一个终端以`root`权限运行`fri`

下载 hook 脚本：

```shell
wget https://github.com/Young-Lord/qq-win-db-key/raw/master/android_hook.py
```

打开 QQ 并完成登录，进入主界面。将 QQ 切换到后台后继续下一步。

在一个没有获得 root 权限的 Termux 终端中运行：

```shell
python android_hook.py
```

此时应当输出`Frida script injected.`，若没有，请检查：

- 是否以`root`权限运行`frida-server`
- 是否以关闭 SELinux （即设置为宽容模式）
- 是否已经关闭`Magisk Hide`与`Shamiko`，并且重启手机
- `frida-server`与 Termux 中的`frida`版本号第一个点号前的数字是否相同
- QQ 版本是否一致

接下来，可以确认命令行是否有输出。

# PC (adb)

你也可以使用`adb`来避免在手机端配置`Termux`。具体过程略。
