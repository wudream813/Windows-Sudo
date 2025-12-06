# Windows-Sudo
一个单文件、静态编译的 Windows 提权工具。它能够以 SYSTEM 或 TrustedInstaller 权限运行命令。

## 核心特性：
- 全权限支持：支持提权至 Administrator, System, TrustedInstaller。
- 让高权限进程直接复用当前终端窗口，支持标准输入输出重定向。
- Session 穿透：自动修正 Token Session ID，支持从 Session 0 (服务/后台) 穿透至当前活动桌面 (WTSActive)。
