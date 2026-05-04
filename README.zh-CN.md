# EnvScope

Language: [English](README.md) | 简体中文

EnvScope 是一个用于 Android 运行环境自检的 APK，重点探测 Frida、Xposed、LSPosed、EdXposed、Substrate、Riru、Zygisk/Magisk 等动态插桩、Hook 或模块化注入痕迹。

项目同时实现 Kotlin 层与 Native C++ 层检测。Kotlin 层负责包名、类加载、调用栈、环境变量、系统属性、端口、进程、挂载表等检查；Native 层负责已加载 so、导出符号、`/proc`、线程名、socket 和 `TracerPid` 的交叉检查。

## 构建

本项目使用 Android Gradle Plugin 8.7.1、Kotlin 1.9.24、compileSdk 35。

```powershell
$env:JAVA_HOME='C:\Users\11980\AppData\Local\Programs\Android Studio\jbr'
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
.\gradlew.bat assembleDebug
```

构建产物：

```text
app/build/outputs/apk/debug/app-debug.apk
```

## 权限说明

- `android.permission.INTERNET`：用于主动连接 `127.0.0.1` / `::1` 上的 Frida 常见端口。
- `android.permission.QUERY_ALL_PACKAGES`：用于枚举安装包并检查 Hook 管理器、Frida Gadget、Magisk/LSPosed 等包名或路径。该权限适合安全自检、企业内部分发或研究用途；如上架应用商店，需要按平台政策说明用途。
- `<queries>`：显式声明常见 Xposed、LSPosed、EdXposed、Substrate、Magisk、Frida 相关包名，提升 Android 11+ 包可见性。

## 检测点

### 1. 已安装 Hook/注入管理器包名

通过 `PackageManager.getPackageInfo()` 查询常见包名：

- Xposed Installer：`de.robv.android.xposed.installer`
- LSPosed：`org.lsposed.manager`
- EdXposed：`org.meowcat.edxposed.manager`、`com.solohsu.android.edxp.manager`
- Riru EdXposed：`com.elderdrivers.riru.edxp.manager`
- LSPatch：`org.lsposed.lspatch`
- TaiChi / VirtualXposed：`me.weishu.exp`、`me.weishu.exposed`、`io.va.exposed`
- Cydia Substrate：`com.saurik.substrate`
- Magisk / Kitsune Mask：`com.topjohnwu.magisk`、`io.github.huskydg.magisk`
- Frida 相关包名：`re.frida.server`、`com.frida.server`、`re.frida.gadget`、`com.frida.gadget`

### 2. 安装包清单关键词扫描

枚举可见安装包的包名、应用标签和 APK 路径，匹配：

```text
frida, xposed, lsposed, lspd, edxposed, riru, zygisk,
substrate, taichi, virtualxposed, lspatch, magisk
```

这可以发现不在精确包名列表内的改名版本、分支版本或模块管理器。

### 3. 运行时可加载 Hook 框架类

通过当前 `ClassLoader`、线程上下文 `ClassLoader` 和系统 `ClassLoader` 尝试加载典型类：

- `de.robv.android.xposed.XposedBridge`
- `de.robv.android.xposed.XposedHelpers`
- `de.robv.android.xposed.XC_MethodHook`
- `de.robv.android.xposed.callbacks.XC_LoadPackage`
- `org.lsposed.lspd.impl.LSPosedBridge`
- `org.lsposed.lspd.impl.LSPosedContext`
- `com.saurik.substrate.MS`
- `re.frida.Gadget`、`com.frida.Gadget`、`frida.Agent`

如果这些类可被加载，通常表示进程内已经存在 Hook 框架或 Gadget 注入环境。

### 4. 线程调用栈 Hook 痕迹

扫描当前进程所有 Java 线程栈，匹配：

```text
xposedbridge, xposedhelpers, handlehookedmethod,
invokeoriginalmethodnative, lsposed, lspd, edxposed,
substrate, frida
```

该检测点用于发现 Xposed/LSPosed hook 调用链、原方法调用桥或 Frida 相关栈帧。

### 5. 线程名关键词

检查 Java 线程名和 `/proc/self/task/*/comm`，覆盖 Frida 常见线程名：

- `gum-js-loop`
- `gmain`
- `gdbus`
- `pool-frida`
- `linjector`

同时匹配 `xposed`、`lsposed`、`lspd`、`riru`、`zygisk` 等关键词。

### 6. `/proc/self/maps` 注入库或 memfd

读取当前进程 maps，查找：

- `libfrida-gadget.so`
- `frida-agent`
- `gum-js-loop`
- `libxposed_art.so`
- `lspd`
- `edxposed`
- `riru`
- `zygisk`
- `substrate`
- `sandhook`
- `yahfa`
- `epic`
- `whale`

该检测点可以发现已加载 native 注入库、内存文件映射、inline hook 框架或 Zygisk/Riru 相关 so。

### 7. 异常可写可执行内存段

扫描 maps 中非系统、非 APEX、非常见 ART JIT 的 `rwx` 映射。该项不是 Frida/Xposed 专属证据，但可作为动态插桩、shellcode、inline hook 的辅助信号。

### 8. ClassLoader / DexPath 注入路径

反射检查 `BaseDexClassLoader` 内部的：

- `dexElements`
- `nativeLibraryDirectories`
- `nativeLibraryPathElements`

如果 dex、apk、jar、so 路径中出现 Frida、Xposed、LSPosed、LSPatch、Substrate、Riru、Zygisk 等关键词，则标记命中。

### 9. 环境变量关键词

扫描 `System.getenv()`，重点覆盖：

- `LD_PRELOAD`
- `CLASSPATH`
- 注入框架添加的自定义环境变量

如果环境变量中出现 `XposedBridge.jar`、`frida`、`substrate` 等关键词，则标记命中。

### 10. 常见框架与服务文件路径

检查常见落点：

- `/system/framework/XposedBridge.jar`
- `/system/bin/app_process_xposed`
- `/system/lib/libxposed_art.so`
- `/data/adb/lspd`
- `/data/adb/modules/zygisk_lsposed`
- `/data/adb/modules/riru_lsposed`
- `/data/adb/modules/edxposed`
- `/data/adb/modules/riru-core`
- `/data/local/tmp/frida-server`
- `/data/local/tmp/libfrida-gadget.so`
- `/system/bin/frida-server`

Android 沙箱可能限制部分路径访问，因此该项适合作为命中证据，不适合作为唯一的未命中依据。

### 11. 系统属性关键词

通过反射 `android.os.SystemProperties.get()` 和执行 `getprop` 扫描属性：

- `persist.sys.xposed`
- `persist.sys.taichi`
- `ro.dalvik.vm.native.bridge`
- `ro.boot.zygisk`
- `persist.zygisk.enabled`
- `ro.magisk.version`
- `ro.lsposed.version`
- `ro.edxposed.version`

同时对完整 `getprop` 输出做关键词匹配。

### 12. Frida 本地端口连接探测

主动连接：

- `127.0.0.1`
- `::1`

端口范围：

- `27040` 到 `27050`
- `23946`

其中 `27042`、`27043` 是 Frida server 的常见默认端口。端口开放会被标记为高风险。

### 13. `/proc/net/tcp` 端口表

读取 `/proc/net/tcp` 和 `/proc/net/tcp6`，查找 Frida 常见端口的十六进制表示，覆盖主动连接失败但端口表可见的情况。

### 14. Unix Domain Socket 关键词

扫描 `/proc/net/unix`，匹配 Frida、gum、LSPosed、LSP、Magisk、Zygisk、Riru 等 socket 名称。

### 15. 进程列表关键词

读取：

- `/proc/[pid]/cmdline`
- `/proc/[pid]/comm`
- `ps -A`
- `ps`

查找 `frida-server`、`lspd`、`zygisk`、`riru`、`xposed` 等进程名或命令行。Android 8+ 对跨进程可见性有限，因此该项同样是命中强、未命中弱。

### 16. `TracerPid` 调试附加状态

读取 `/proc/self/status` 中的 `TracerPid`。非 0 表示当前进程被 `ptrace` 附加，可能来自调试器、Frida 或其他动态分析工具。

### 17. 挂载表模块痕迹

扫描：

- `/proc/self/mountinfo`
- `/proc/mounts`

查找 `magisk`、`zygisk`、`riru`、`lsposed`、`lspd`、`edxposed`、`xposed`、`shamiko` 等模块挂载痕迹。

### 18. Native 层自检

C++ 层执行独立检查：

- `dl_iterate_phdr` 枚举已加载 so，查找 Frida/Xposed/LSPosed/Riru/Zygisk/Substrate 关键词。
- `dlsym(RTLD_DEFAULT, ...)` 查找 `frida_agent_main`、`gum_interceptor_attach`、`MSHookFunction`、`xposedCallHandler` 等导出符号。
- 读取 `/proc/self/maps` 做 native 侧二次 maps 扫描。
- 读取 `/proc/self/task/*/comm` 做 native 线程名扫描。
- 读取 `/proc/net/tcp`、`/proc/net/tcp6` 查找 Frida 常见端口。
- 读取 `/proc/net/unix` 查找注入框架 socket。
- 读取 `/proc/self/status` 检查 `TracerPid`。

Native 层用于补充 Kotlin 层被 Hook、API 被替换或 Java 反射受限时的检测覆盖。

## 风险等级

应用会根据命中项的严重度累计风险分：

- `严重`：进程内类、maps、native so、导出符号等强证据。
- `高`：端口、进程、线程、文件路径、调试附加等高置信信号。
- `中`：系统属性、安装包清单、socket、挂载表等环境信号。
- `低`：可写可执行内存段等辅助信号。

## 局限性

- Frida、LSPosed、Magisk/Zygisk 等工具可以隐藏包名、进程、端口、maps 或 `/proc` 内容，任何单点检测都可能被绕过。
- Android 版本、ROM、SELinux、应用沙箱和包可见性策略会影响文件、进程、socket、安装包枚举结果。
- 某些关键词检测可能产生误报，例如第三方安全工具、调试工具或自研模块路径中包含相同关键词。
- 建议将 EnvScope 的结果作为多信号综合判断，不要只依赖单个检测点。
