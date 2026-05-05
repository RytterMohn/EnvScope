# EnvScope 检测实现详解

本文档基于当前仓库源码编写，说明 EnvScope 如何完成 Frida、Xposed、LSPosed、EdXposed、Substrate、Riru、Zygisk/Magisk 等运行环境痕迹检测。每个检测项都包含检测方法、检测原理、对应代码位置、关键代码逻辑、命中证据格式和注意点。

## 1. 整体架构

EnvScope 是一个 Android App，检测逻辑分为 Kotlin 层和 Native C++ 层：

- UI 层：`app/src/main/java/com/example/envscope/MainActivity.kt`
- Kotlin 检测层：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt`
- 结果模型与风险评分：`app/src/main/java/com/example/envscope/detection/DetectionModels.kt`
- Native 检测层：`app/src/main/cpp/native-lib.cpp`
- Native 构建配置：`app/src/main/cpp/CMakeLists.txt`
- 权限与包可见性配置：`app/src/main/AndroidManifest.xml`

### 1.1 扫描入口

代码位置：

- `MainActivity.onCreate()`：`app/src/main/java/com/example/envscope/MainActivity.kt:23`
- `MainActivity.runScan()`：`app/src/main/java/com/example/envscope/MainActivity.kt:32`
- `EnvironmentScanner.scan()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:132`

关键代码：

```kotlin
binding.scanButton.setOnClickListener { runScan() }
runScan()
```

```kotlin
Thread {
    val report = EnvironmentScanner.scan(this@MainActivity) {
        collectNativeSignals().toList()
    }
    runOnUiThread {
        renderReport(report)
        binding.scanButton.isEnabled = true
    }
}.start()
```

实现说明：

- App 启动后会自动执行一次扫描。
- 用户点击重新扫描按钮时再次执行 `runScan()`。
- 扫描运行在后台线程，避免阻塞 UI。
- `EnvironmentScanner.scan()` 负责执行所有 Kotlin 检测项。
- Native 层通过 `collectNativeSignals()` 作为回调传入 Kotlin 扫描器。
- 扫描结束后生成 `ScanReport`，再由 `renderReport()` 渲染到界面。

### 1.2 Native 库加载

代码位置：

- `MainActivity.collectNativeSignals()`：`app/src/main/java/com/example/envscope/MainActivity.kt:149`
- `System.loadLibrary("envscope")`：`app/src/main/java/com/example/envscope/MainActivity.kt:153`
- JNI 函数：`app/src/main/cpp/native-lib.cpp:239`
- CMake so 定义：`app/src/main/cpp/CMakeLists.txt:27`

关键代码：

```kotlin
external fun collectNativeSignals(): Array<String>

companion object {
    init {
        System.loadLibrary("envscope")
    }
}
```

```cpp
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_envscope_MainActivity_collectNativeSignals(JNIEnv* env, jobject) {
    const std::vector<std::string> signals = collectSignals();
    ...
}
```

实现说明：

- C++ 文件被编译为名为 `envscope` 的共享库。
- Kotlin 通过 `System.loadLibrary("envscope")` 加载它。
- JNI 导出函数名与 Kotlin 的 `collectNativeSignals()` 绑定。
- Native 层返回字符串数组，每一项是命中的证据。
- Kotlin 层把这些证据包装成一个 `DetectionCheck`。

## 2. 权限与构建配置

### 2.1 Android 权限

代码位置：

- `app/src/main/AndroidManifest.xml:5`
- `app/src/main/AndroidManifest.xml:6`
- `app/src/main/AndroidManifest.xml:10`

关键代码：

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission
    android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission" />
```

```xml
<queries>
    <package android:name="de.robv.android.xposed.installer" />
    <package android:name="org.lsposed.manager" />
    <package android:name="com.topjohnwu.magisk" />
    <package android:name="re.frida.server" />
    ...
</queries>
```

实现说明：

- `INTERNET` 用于主动连接 `127.0.0.1` 和 `::1` 上的 Frida 常见端口。
- `QUERY_ALL_PACKAGES` 用于枚举安装包，支撑包名和应用标签关键词检测。
- `<queries>` 声明常见 Hook 管理器、Magisk、Frida 包名，提高 Android 11 及以上系统的包可见性。

### 2.2 Native 构建

代码位置：

- `app/build.gradle.kts:36`
- `app/src/main/cpp/CMakeLists.txt:27`
- `app/src/main/cpp/CMakeLists.txt:34`

关键代码：

```kotlin
externalNativeBuild {
    cmake {
        path = file("src/main/cpp/CMakeLists.txt")
        version = "3.22.1"
    }
}
```

```cmake
add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        dl
        log)
```

实现说明：

- Gradle 使用 CMake 构建 Native so。
- `dl` 用于 `dlsym()`、`dl_iterate_phdr()` 相关能力。
- Native so 被打包进 APK，运行时由 Kotlin 加载。

## 3. 结果模型与风险评分

代码位置：

- `DetectionArea`：`app/src/main/java/com/example/envscope/detection/DetectionModels.kt:3`
- `Severity`：`app/src/main/java/com/example/envscope/detection/DetectionModels.kt:11`
- `DetectionCheck`：`app/src/main/java/com/example/envscope/detection/DetectionModels.kt:19`
- `ScanReport`：`app/src/main/java/com/example/envscope/detection/DetectionModels.kt:30`
- `EnvironmentScanner.check()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:521`

关键代码：

```kotlin
enum class Severity(val label: String, val score: Int) {
    INFO("信息", 0),
    LOW("低", 1),
    MEDIUM("中", 2),
    HIGH("高", 3),
    CRITICAL("严重", 4)
}
```

```kotlin
data class DetectionCheck(
    val id: String,
    val area: DetectionArea,
    val title: String,
    val detail: String,
    val severity: Severity,
    val hit: Boolean,
    val evidence: List<String> = emptyList(),
    val note: String? = null
)
```

```kotlin
val riskScore: Int = hits.sumOf { it.severity.score.coerceAtLeast(1) }

val riskLabel: String = when {
    hits.any { it.severity == Severity.CRITICAL } || riskScore >= 10 -> "高危"
    riskScore >= 5 -> "高"
    riskScore >= 2 -> "中"
    riskScore == 1 -> "低"
    else -> "未发现明显风险"
}
```

```kotlin
private fun check(...): DetectionCheck {
    val normalized = evidence.map(::compact).filter { it.isNotBlank() }.distinct().take(30)
    return DetectionCheck(
        id = id,
        area = area,
        title = title,
        detail = detail,
        severity = severity,
        hit = normalized.isNotEmpty(),
        evidence = normalized
    )
}
```

实现说明：

- 每个检测方法最终返回一个 `DetectionCheck`。
- 只要 `evidence` 非空，就认为该检测项 `hit = true`。
- 证据会经过 `compact()` 规整：去掉空字符、压缩空白、限制长度。
- 每个检测项最多保留 30 条证据。
- Native 检测项最多先取 40 条 Native 证据，再进入统一 `check()` 归一化。
- 风险分是所有命中项严重等级分数之和。
- 只要存在 `CRITICAL` 命中，整体风险直接进入“高危”。

## 4. 公共关键词与辅助函数

### 4.1 关键词列表

代码位置：

- `knownPackages`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:16`
- `classNames`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:37`
- `knownPaths`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:53`
- `packageTokens`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:79`
- `runtimeTokens`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:94`
- `stackTokens`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:118`
- `fridaPorts`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:130`

关键代码：

```kotlin
private val packageTokens = listOf(
    "frida", "xposed", "lsposed", "lspd", "edxposed", "riru",
    "zygisk", "substrate", "taichi", "virtualxposed", "lspatch", "magisk"
)
```

```kotlin
private val runtimeTokens = listOf(
    "frida", "gum-js-loop", "gmain", "gdbus", "linjector",
    "xposed", "lsposed", "lspd", "edxposed", "riru", "zygisk",
    "substrate", "taichi", "virtualxposed", "lspatch", "magisk",
    "shamiko", "sandhook", "yahfa", "epic", "whale"
)
```

```kotlin
private val fridaPorts = (27040..27050).toList() + listOf(23946)
```

实现说明：

- `packageTokens` 面向安装包、应用标签、APK 路径。
- `runtimeTokens` 面向运行时痕迹，包括 Frida 线程、Hook 框架、Magisk 模块、常见 inline hook 框架。
- `stackTokens` 面向 Java 调用栈中的类名和方法名。
- `fridaPorts` 覆盖 Frida 默认端口 `27042`、`27043` 以及邻近端口，并额外检测 `23946`。

### 4.2 证据匹配辅助函数

代码位置：

- `matchingLines()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:611`
- `matchIfSuspicious()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:619`
- `readLines()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:626`
- `runCommand()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:646`
- `compact()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:666`

关键代码：

```kotlin
private fun matchingLines(label: String, lines: List<String>, tokens: List<String>): List<String> {
    return lines.mapNotNull { line ->
        val lower = line.lowercase(Locale.US)
        val token = tokens.firstOrNull { lower.contains(it) } ?: return@mapNotNull null
        compact("$label token=$token $line")
    }.distinct().take(30)
}
```

```kotlin
private fun matchIfSuspicious(label: String, value: String?, tokens: List<String>): List<String> {
    if (value.isNullOrBlank()) return emptyList()
    val lower = value.lowercase(Locale.US)
    val token = tokens.firstOrNull { lower.contains(it) } ?: return emptyList()
    return listOf(compact("$label token=$token $value"))
}
```

实现说明：

- 大多数检测项都是“读取数据源 -> 转小写 -> 关键词匹配 -> 生成证据”。
- `matchingLines()` 用于多行文件或命令输出。
- `matchIfSuspicious()` 用于单个字符串字段。
- `readLines()` 对 `/proc` 文件读取失败做容错，失败时返回空列表。
- `runCommand()` 用 `ProcessBuilder` 执行命令，并设置读取线程超时，避免命令卡死。

## 5. 扫描编排顺序

代码位置：

- `EnvironmentScanner.scan()`：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:132`

关键代码：

```kotlin
checks += checkKnownPackages(appContext)
checks += checkPackageInventory(appContext)
checks += checkClassLoader(appContext)
checks += checkThreadStacks()
checks += checkThreadNames()
checks += checkSelfMaps()
checks += checkExecutableMaps()
checks += checkClassLoaderPaths(appContext)
checks += checkEnvironmentVariables()
checks += checkKnownFiles()
checks += checkSystemProperties()
checks += checkLocalhostPorts()
checks += checkProcNetTcp()
checks += checkProcNetUnix()
checks += checkProcesses()
checks += checkTracerPid()
checks += checkMountInfo()
checks += checkNative(nativeCollector)
```

实现说明：

- 一次扫描固定执行 18 个检测项。
- 前 17 个由 Kotlin 实现。
- 第 18 个 `checkNative()` 调用 Native 回调，汇总 C++ 层的多种检测信号。
- 每个检测项独立失败容错，失败通常表现为无证据，而不是中断整个扫描。

## 6. Kotlin 层检测项

### 6.0 Kotlin 检测函数索引

| 序号 | 检测 ID | Kotlin 函数 | 源码位置 |
| --- | --- | --- | --- |
| 1 | `pkg-known` | `checkKnownPackages()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:160` |
| 2 | `pkg-inventory` | `checkPackageInventory()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:177` |
| 3 | `class-loader` | `checkClassLoader()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:200` |
| 4 | `thread-stack` | `checkThreadStacks()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:227` |
| 5 | `thread-name` | `checkThreadNames()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:245` |
| 6 | `maps-keywords` | `checkSelfMaps()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:262` |
| 7 | `maps-rwx` | `checkExecutableMaps()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:278` |
| 8 | `classloader-path` | `checkClassLoaderPaths()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:300` |
| 9 | `env-vars` | `checkEnvironmentVariables()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:315` |
| 10 | `known-files` | `checkKnownFiles()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:331` |
| 11 | `system-properties` | `checkSystemProperties()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:350` |
| 12 | `frida-ports-connect` | `checkLocalhostPorts()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:387` |
| 13 | `proc-net-tcp` | `checkProcNetTcp()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:412` |
| 14 | `proc-net-unix` | `checkProcNetUnix()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:429` |
| 15 | `process-list` | `checkProcesses()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:445` |
| 16 | `tracer-pid` | `checkTracerPid()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:462` |
| 17 | `mount-info` | `checkMountInfo()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:476` |
| 18 | `native-scan` | `checkNative()` | `app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:492` |

### 6.1 已安装 Hook/注入管理器包名

检测 ID：`pkg-known`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:160`
- 包名列表：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:16`
- 包查询辅助函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:538`
- Manifest 包可见性：`app/src/main/AndroidManifest.xml:10`

关键代码：

```kotlin
private val knownPackages = listOf(
    KnownPackage("de.robv.android.xposed.installer", "Xposed Installer"),
    KnownPackage("org.lsposed.manager", "LSPosed Manager"),
    KnownPackage("com.topjohnwu.magisk", "Magisk"),
    KnownPackage("re.frida.server", "Frida server package"),
    KnownPackage("re.frida.gadget", "Frida Gadget package"),
    ...
)
```

```kotlin
private fun checkKnownPackages(context: Context): DetectionCheck {
    val pm = context.packageManager
    val evidence = knownPackages.mapNotNull { known ->
        val info = findPackage(pm, known.packageName) ?: return@mapNotNull null
        val source = info.applicationInfo?.sourceDir.orEmpty()
        compact("${known.packageName} (${known.label}) source=$source")
    }
    return check(
        id = "pkg-known",
        area = DetectionArea.XPOSED,
        severity = Severity.HIGH,
        evidence = evidence
    )
}
```

检测原理：

很多 Hook 框架、注入工具或 Root 模块管理器在设备上会保留固定包名。例如 Xposed Installer、LSPosed Manager、Magisk、Frida server/Gadget 包。如果 `PackageManager.getPackageInfo()` 能查到这些包，说明设备上存在对应管理器或组件，是较强的环境风险信号。

实现细节：

- 遍历 `knownPackages`。
- 对每个包名调用 `findPackage()`。
- Android 13 及以上使用 `PackageManager.PackageInfoFlags.of(0)`，旧版本使用 deprecated 的 `getPackageInfo(packageName, 0)`。
- 查到包后，把包名、标签、安装源路径 `sourceDir` 作为证据。

命中证据格式：

```text
com.topjohnwu.magisk (Magisk) source=/data/app/...
```

注意点：

- Android 11 以后包可见性受限，所以 Manifest 中显式声明了 `<queries>`，并申请了 `QUERY_ALL_PACKAGES`。
- 包名可以被隐藏、改名或通过策略过滤，因此未命中不代表环境一定干净。

### 6.2 安装包清单关键词扫描

检测 ID：`pkg-inventory`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:177`
- 关键词列表：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:79`
- 安装包枚举辅助函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:549`

关键代码：

```kotlin
private fun checkPackageInventory(context: Context): DetectionCheck {
    val pm = context.packageManager
    val packages = installedPackages(pm)
    val evidence = packages.mapNotNull { info ->
        val packageName = info.packageName.orEmpty()
        val sourceDir = info.applicationInfo?.sourceDir.orEmpty()
        val label = runCatching {
            info.applicationInfo?.loadLabel(pm)?.toString().orEmpty()
        }.getOrDefault("")
        val probe = "$packageName $sourceDir $label".lowercase(Locale.US)
        val token = packageTokens.firstOrNull { probe.contains(it) } ?: return@mapNotNull null
        compact("token=$token package=$packageName label=$label source=$sourceDir")
    }
    ...
}
```

检测原理：

固定包名检测只能覆盖已知工具的默认包名。实际环境中可能存在改名版本、分支版本、重新打包版本或模块管理器。安装包清单关键词扫描通过枚举可见应用的包名、应用标签和 APK 路径，查找 `frida`、`xposed`、`lsposed`、`magisk` 等关键词，扩大覆盖范围。

实现细节：

- 使用 `PackageManager.getInstalledPackages()` 枚举可见安装包。
- 拼接 `packageName`、`sourceDir`、应用 `label`。
- 统一转为小写后与 `packageTokens` 匹配。
- 命中后记录命中的 token、包名、标签和 APK 路径。

命中证据格式：

```text
token=lsposed package=org.lsposed.manager label=LSPosed source=/data/app/...
```

注意点：

- 关键词匹配可能出现误报，例如某个普通安全工具包名或标签里包含相同词。
- 该检测的严重级别是 `MEDIUM`，低于固定包名检测。

### 6.3 运行时可加载 Hook 框架类

检测 ID：`class-loader`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:200`
- 类名列表：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:37`

关键代码：

```kotlin
private val classNames = listOf(
    "de.robv.android.xposed.XposedBridge",
    "de.robv.android.xposed.XposedHelpers",
    "org.lsposed.lspd.impl.LSPosedBridge",
    "com.saurik.substrate.MS",
    "re.frida.Gadget",
    "com.frida.Gadget",
    "frida.Agent"
)
```

```kotlin
val loaders = listOfNotNull(
    context.classLoader,
    Thread.currentThread().contextClassLoader,
    ClassLoader.getSystemClassLoader()
).distinct()

classNames.forEach { className ->
    loaders.forEach { loader ->
        val loaded = runCatching {
            Class.forName(className, false, loader)
        }.isSuccess
        if (loaded) {
            evidence += compact("$className via ${loader.javaClass.name}")
        }
    }
}
```

检测原理：

Xposed、LSPosed、Substrate、Frida Gadget 等框架通常会向目标进程注入 Java 类或让相关类对目标 ClassLoader 可见。如果目标进程能通过当前 ClassLoader、线程上下文 ClassLoader 或系统 ClassLoader 加载这些典型类名，说明进程内很可能存在 Hook 框架或 Gadget 注入环境。

实现细节：

- 构造三个 ClassLoader 来源：
  - App 的 `context.classLoader`
  - 当前线程的 `contextClassLoader`
  - 系统 ClassLoader
- 对每个典型类名调用 `Class.forName(className, false, loader)`。
- 第二个参数传 `false`，只检测能否加载，不触发类初始化。
- 成功加载即记录类名和具体 ClassLoader 类型。

命中证据格式：

```text
de.robv.android.xposed.XposedBridge via dalvik.system.PathClassLoader
```

注意点：

- 这是 `CRITICAL` 级别，因为它是进程内强证据。
- 如果 Hook 框架隐藏类、隔离 ClassLoader 或拦截 `Class.forName()`，可能绕过此检测。

### 6.4 线程调用栈 Hook 痕迹

检测 ID：`thread-stack`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:227`
- 调用栈关键词：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:118`

关键代码：

```kotlin
private val stackTokens = listOf(
    "xposedbridge",
    "xposedhelpers",
    "handlehookedmethod",
    "invokeoriginalmethodnative",
    "lsposed",
    "lspd",
    "edxposed",
    "substrate",
    "frida"
)
```

```kotlin
val evidence = Thread.getAllStackTraces().flatMap { (thread, stackTrace) ->
    stackTrace.mapNotNull { frame ->
        val value = "${thread.name}: ${frame.className}.${frame.methodName}(${frame.fileName}:${frame.lineNumber})"
        val lower = value.lowercase(Locale.US)
        if (stackTokens.any { lower.contains(it) }) compact(value) else null
    }
}
```

检测原理：

Hook 框架在调用目标方法时，调用栈中可能出现桥接类、Hook 分发方法或原始方法调用桥。例如 Xposed 的 `handleHookedMethod`、`invokeOriginalMethodNative`，或 LSPosed、Substrate、Frida 相关类名。扫描所有 Java 线程栈可以捕捉正在发生的 Hook 调用链。

实现细节：

- 调用 `Thread.getAllStackTraces()` 获取当前进程所有 Java 线程栈。
- 把线程名、类名、方法名、文件名和行号拼成字符串。
- 与 `stackTokens` 做小写关键词匹配。
- 命中后记录完整栈帧摘要。

命中证据格式：

```text
main: de.robv.android.xposed.XposedBridge.handleHookedMethod(XposedBridge.java:...)
```

注意点：

- 该检测依赖采样时机，只有栈上正好出现相关调用才会命中。
- Hook 框架空闲时可能没有明显栈帧。

### 6.5 线程名关键词

检测 ID：`thread-name`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:245`
- Native 线程名读取：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:587`
- 运行时关键词：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:94`

关键代码：

```kotlin
val javaThreads = Thread.getAllStackTraces().keys.map { "java:${it.name}" }
val nativeThreads = readTaskNames().map { "native:$it" }
val evidence = (javaThreads + nativeThreads).mapNotNull { name ->
    val lower = name.lowercase(Locale.US)
    if (runtimeTokens.any { lower.contains(it) }) compact(name) else null
}
```

```kotlin
private fun readTaskNames(): List<String> {
    val taskDir = File("/proc/self/task")
    return runCatching {
        taskDir.listFiles().orEmpty().mapNotNull { task ->
            val comm = File(task, "comm").readTextOrEmpty().trim()
            if (comm.isBlank()) null else "${task.name}:$comm"
        }
    }.getOrDefault(emptyList())
}
```

检测原理：

Frida、Gum、GLib/GDBus 和一些注入器会创建特征明显的线程，例如 `gum-js-loop`、`gmain`、`gdbus`、`pool-frida`、`linjector`。LSPosed、Riru、Zygisk 等也可能在线程名中留下痕迹。Android 的 Java 线程名和 Linux `/proc/self/task/*/comm` 可以从两个层面观察线程。

实现细节：

- Java 层通过 `Thread.getAllStackTraces().keys` 获取 Java 线程对象。
- Native/Linux 层通过 `/proc/self/task/<tid>/comm` 获取线程 comm 名。
- 合并两类线程名后用 `runtimeTokens` 匹配。

命中证据格式：

```text
java:gum-js-loop
native:12345:gmain
```

注意点：

- 线程名可以被改名隐藏。
- `gmain`、`gdbus` 可能在某些非 Frida 场景出现，因此需要结合其他检测项判断。

### 6.6 进程 maps 中的注入库或 memfd

检测 ID：`maps-keywords`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:262`
- 文件读取辅助函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:626`
- 行匹配辅助函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:611`

关键代码：

```kotlin
private fun checkSelfMaps(): DetectionCheck {
    val evidence = matchingLines(
        label = "/proc/self/maps",
        lines = readLines("/proc/self/maps", 6000),
        tokens = runtimeTokens
    )
    return check(
        id = "maps-keywords",
        area = DetectionArea.FRIDA,
        severity = Severity.CRITICAL,
        evidence = evidence
    )
}
```

检测原理：

Linux 进程的 `/proc/self/maps` 记录当前进程所有内存映射，包括加载的 so、apk、dex、匿名映射和 memfd。Frida Gadget、Xposed native bridge、LSPosed、Riru、Zygisk、Substrate 或 inline hook 框架的库名、路径名、memfd 名可能出现在 maps 中。

实现细节：

- 读取 `/proc/self/maps` 前 6000 行。
- 对每行使用 `runtimeTokens` 关键词匹配。
- 命中后把原始 maps 行和 token 一起作为证据。

命中证据格式：

```text
/proc/self/maps token=frida 7a... /data/local/tmp/libfrida-gadget.so
```

注意点：

- 这是 `CRITICAL` 级别，因为它代表进程内已加载或映射的强证据。
- 如果系统或隐藏模块过滤 `/proc/self/maps`，可能无法看到真实映射。

### 6.7 异常可写可执行内存段

检测 ID：`maps-rwx`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:278`

关键代码：

```kotlin
val parts = line.trim().split(Regex("\\s+"))
val perms = parts.getOrNull(1).orEmpty()
val lower = line.lowercase(Locale.US)
val suspicious = perms.startsWith("rwx") &&
    !lower.contains("/system/") &&
    !lower.contains("/apex/") &&
    !lower.contains("[anon:dalvik") &&
    !lower.contains("/memfd:jit-cache")
if (suspicious) compact(line) else null
```

检测原理：

正常应用代码通常不应存在大量同时可写和可执行的内存映射。动态插桩、shellcode、inline hook 或 JIT/代码生成可能产生 `rwx` 映射。该检测不指向某个具体框架，但可作为动态修改代码行为的辅助信号。

实现细节：

- 读取 `/proc/self/maps`。
- 解析每行第二列权限字段。
- 如果权限以 `rwx` 开头，则认为同时可读、可写、可执行。
- 排除常见系统路径 `/system/`、APEX 路径 `/apex/`、Dalvik 匿名映射和 ART JIT cache。

命中证据格式：

```text
7a...-7a... rwxp 00000000 00:00 0 [anon:...]
```

注意点：

- 严重级别是 `LOW`，因为它不是 Frida/Xposed 专属证据。
- 部分合法 JIT、引擎或防护 SDK 也可能产生类似映射。

### 6.8 ClassLoader/DexPath 注入路径

检测 ID：`classloader-path`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:300`
- ClassLoader 反射辅助函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:560`

关键代码：

```kotlin
val evidence = mutableListOf<String>()
evidence += matchIfSuspicious("application source", context.applicationInfo.sourceDir, runtimeTokens)
evidence += matchIfSuspicious("native library dir", context.applicationInfo.nativeLibraryDir, runtimeTokens)
evidence += inspectClassLoaderPathList(context.classLoader)
```

```kotlin
listOf("dexElements", "nativeLibraryDirectories", "nativeLibraryPathElements").forEach { fieldName ->
    val value = runCatching {
        pathList.javaClass.getDeclaredField(fieldName).apply { isAccessible = true }.get(pathList)
    }.getOrNull()
    val text = when (value) {
        is Array<*> -> value.joinToString()
        is Collection<*> -> value.joinToString()
        else -> value?.toString().orEmpty()
    }
    evidence += matchIfSuspicious(fieldName, text, runtimeTokens)
}
```

检测原理：

Android 的 `BaseDexClassLoader` 内部维护 dex 路径和 native library 路径。LSPatch、VirtualXposed、Frida Gadget 或其他注入方案可能把额外 dex、apk、jar、so 路径加入 ClassLoader。反射检查这些路径可以发现注入组件或 Hook 框架路径。

实现细节：

- 先检查当前应用 APK 源路径 `applicationInfo.sourceDir`。
- 再检查当前应用 native library 目录 `nativeLibraryDir`。
- 反射查找 ClassLoader 继承链上的 `pathList` 字段。
- 从 `pathList` 中读取：
  - `dexElements`
  - `nativeLibraryDirectories`
  - `nativeLibraryPathElements`
- 把字段值转为字符串后用 `runtimeTokens` 匹配。

命中证据格式：

```text
dexElements token=lspatch [zip file "/data/app/.../lspatch/..."]
```

注意点：

- Android 版本或厂商实现变化可能导致反射字段不可访问。
- 反射失败时该检测返回空证据，不中断扫描。

### 6.9 环境变量关键词

检测 ID：`env-vars`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:315`

关键代码：

```kotlin
val evidence = System.getenv().mapNotNull { (key, value) ->
    val probe = "$key=$value"
    val lower = probe.lowercase(Locale.US)
    if (runtimeTokens.any { lower.contains(it) }) compact(probe) else null
}
```

检测原理：

某些注入或调试环境会通过环境变量传递加载路径、启动参数或桥接信息。例如 `LD_PRELOAD`、`CLASSPATH` 或自定义变量中可能出现 XposedBridge、Frida、Substrate 等关键词。

实现细节：

- 调用 `System.getenv()` 获取当前进程可见环境变量。
- 拼接 `key=value`。
- 使用 `runtimeTokens` 进行关键词匹配。
- 命中后记录完整环境变量摘要。

命中证据格式：

```text
LD_PRELOAD=/data/local/tmp/libfrida-gadget.so
```

注意点：

- Android App 进程通常看不到完整系统环境。
- 大多数现代注入框架不一定依赖环境变量，因此该项是 `MEDIUM` 辅助信号。

### 6.10 常见框架与服务文件路径

检测 ID：`known-files`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:331`
- 路径列表：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:53`

关键代码：

```kotlin
private val knownPaths = listOf(
    "/system/framework/XposedBridge.jar",
    "/system/bin/app_process_xposed",
    "/system/lib/libxposed_art.so",
    "/data/adb/lspd",
    "/data/adb/modules/zygisk_lsposed",
    "/data/local/tmp/frida-server",
    "/data/local/tmp/libfrida-gadget.so",
    "/system/bin/frida-server",
    ...
)
```

```kotlin
val evidence = knownPaths.mapNotNull { path ->
    val file = File(path)
    if (runCatching { file.exists() }.getOrDefault(false)) {
        compact("$path readable=${file.canRead()} directory=${file.isDirectory}")
    } else {
        null
    }
}
```

检测原理：

一些框架或服务在设备上有常见落点。例如旧 Xposed 的 `XposedBridge.jar` 和 `app_process_xposed`，Magisk 模块目录下的 LSPosed/Riru/Zygisk 模块，或测试环境里放在 `/data/local/tmp` 的 `frida-server`、`libfrida-gadget.so`。检测这些路径是否存在可以作为环境风险信号。

实现细节：

- 遍历 `knownPaths`。
- 对每个路径调用 `File.exists()`。
- 如果存在，记录路径、是否可读、是否目录。

命中证据格式：

```text
/data/adb/modules/zygisk_lsposed readable=false directory=true
```

注意点：

- Android 沙箱和 SELinux 可能限制访问部分路径。
- `exists()` 失败不一定代表文件不存在，也可能是权限限制或路径被隐藏。

### 6.11 系统属性关键词

检测 ID：`system-properties`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:350`
- SystemProperties 反射：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:638`
- 命令执行：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:646`

关键代码：

```kotlin
val specificKeys = listOf(
    "vxp",
    "vxp_user",
    "persist.sys.xposed",
    "persist.sys.taichi",
    "ro.dalvik.vm.native.bridge",
    "ro.boot.zygisk",
    "persist.zygisk.enabled",
    "ro.magisk.version",
    "ro.lsposed.version",
    "ro.edxposed.version"
)
```

```kotlin
evidence += specificKeys.mapNotNull { key ->
    val value = getSystemProperty(key)
    if (value.isNotBlank() && runtimeTokens.any { value.lowercase(Locale.US).contains(it) || key.contains(it) }) {
        compact("$key=$value")
    } else {
        null
    }
}
evidence += matchingLines(
    label = "getprop",
    lines = runCommand(listOf("getprop"), 1200),
    tokens = runtimeTokens
)
```

```kotlin
private fun getSystemProperty(key: String): String {
    return runCatching {
        val clazz = Class.forName("android.os.SystemProperties")
        val method = clazz.getDeclaredMethod("get", String::class.java)
        method.invoke(null, key) as? String
    }.getOrNull().orEmpty()
}
```

检测原理：

系统属性可能暴露虚拟框架、Xposed、Riru、Zygisk、Magisk、LSPosed、EdXposed 等环境信息。例如某些 ROM、模块或工具会设置 `ro.boot.zygisk`、`ro.magisk.version`、`ro.lsposed.version` 等属性。除了读取特定 key，项目还执行 `getprop` 并对完整输出做关键词扫描。

实现细节：

- 通过反射调用隐藏 API `android.os.SystemProperties.get()`。
- 对一组重点 key 单独读取。
- 如果 key 或 value 中出现运行时关键词，则生成证据。
- 同时执行 `getprop` 命令，读取输出并用 `runtimeTokens` 匹配。
- `runCommand()` 设置读取超时，避免命令卡住。

命中证据格式：

```text
ro.boot.zygisk=1
getprop token=magisk [ro.magisk.version]: [...]
```

注意点：

- 系统属性可被隐藏或清理。
- `getprop` 输出里的关键词也可能来自无害属性名或调试环境。

### 6.12 Frida 本地端口连接探测

检测 ID：`frida-ports-connect`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:387`
- 端口列表：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:130`
- 网络权限：`app/src/main/AndroidManifest.xml:5`

关键代码：

```kotlin
private val fridaPorts = (27040..27050).toList() + listOf(23946)
```

```kotlin
val hosts = listOf("127.0.0.1", "::1")
hosts.forEach { host ->
    fridaPorts.forEach { port ->
        val reachable = runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 120)
            }
        }.isSuccess
        if (reachable) {
            evidence += "$host:$port accepts TCP connection"
        }
    }
}
```

检测原理：

Frida server 默认常监听本机 TCP 端口，常见默认端口是 `27042` 和 `27043`。如果 App 能连接到本机对应端口，说明设备上可能运行着 Frida server 或兼容服务。项目扩展检测 `27040..27050` 和 `23946`，覆盖默认端口附近的改动。

实现细节：

- 对 IPv4 loopback `127.0.0.1` 和 IPv6 loopback `::1` 都执行检测。
- 对每个端口创建 Socket 并尝试连接。
- 连接超时时间为 120 ms。
- 连接成功即记录 host 和 port。

命中证据格式：

```text
127.0.0.1:27042 accepts TCP connection
```

注意点：

- 需要 `INTERNET` 权限。
- 开放端口不一定就是 Frida，也可能是其他本地服务，所以需结合其他证据。
- Frida 可以改端口、使用非 TCP 通道或隐藏监听。

### 6.13 `/proc/net/tcp` 端口表

检测 ID：`proc-net-tcp`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:412`

关键代码：

```kotlin
val hexPorts = fridaPorts.map { "%04X".format(Locale.US, it) }.toSet()
val evidence = (readLines("/proc/net/tcp", 2000) + readLines("/proc/net/tcp6", 2000)).mapNotNull { line ->
    val upper = line.uppercase(Locale.US)
    val match = hexPorts.firstOrNull { upper.contains(":$it") } ?: return@mapNotNull null
    compact("port=0x$match $line")
}
```

检测原理：

Linux 的 `/proc/net/tcp` 和 `/proc/net/tcp6` 会列出 TCP socket 表，端口以十六进制表示。即使主动连接端口失败，端口表里仍可能看到 Frida 常见端口的监听或连接记录。

实现细节：

- 把 `fridaPorts` 转成四位大写十六进制字符串。
- 读取 `/proc/net/tcp` 和 `/proc/net/tcp6`。
- 查找形如 `:69A2` 的端口十六进制片段。
- 命中后记录端口十六进制值和原始行。

命中证据格式：

```text
port=0x69A2   0: 0100007F:69A2 ...
```

注意点：

- 当前实现是字符串包含匹配，不区分本地端口、远端端口或连接状态。
- Android 版本和 SELinux 策略可能限制 `/proc/net/tcp` 可见性。

### 6.14 Unix Domain Socket 关键词

检测 ID：`proc-net-unix`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:429`

关键代码：

```kotlin
val evidence = matchingLines(
    label = "/proc/net/unix",
    lines = readLines("/proc/net/unix", 4000),
    tokens = runtimeTokens
)
```

检测原理：

部分注入框架、守护进程或模块会创建 Unix Domain Socket，用于进程间通信、控制通道或服务注册。Socket 名称中可能包含 `frida`、`gum`、`lsposed`、`magisk`、`zygisk`、`riru` 等痕迹。

实现细节：

- 读取 `/proc/net/unix` 前 4000 行。
- 使用 `runtimeTokens` 匹配每行。
- 命中后记录 token 和原始 socket 表行。

命中证据格式：

```text
/proc/net/unix token=frida 0000000000000000: ... @frida...
```

注意点：

- Socket 名称可被随机化或隐藏。
- Android 系统策略可能限制可见 socket。

### 6.15 进程列表关键词

检测 ID：`process-list`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:445`
- `/proc` 进程扫描辅助函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:597`

关键代码：

```kotlin
val evidence = mutableListOf<String>()
evidence += scanProcProcesses()
evidence += matchingLines("ps -A", runCommand(listOf("ps", "-A"), 1800), runtimeTokens)
if (evidence.isEmpty()) {
    evidence += matchingLines("ps", runCommand(listOf("ps"), 1800), runtimeTokens)
}
```

```kotlin
private fun scanProcProcesses(): List<String> {
    val proc = File("/proc")
    return runCatching {
        proc.listFiles().orEmpty().filter { it.name.all(Char::isDigit) }.flatMap { dir ->
            val cmdline = File(dir, "cmdline").readTextOrEmpty().replace('\u0000', ' ').trim()
            val comm = File(dir, "comm").readTextOrEmpty().trim()
            listOfNotNull(
                matchIfSuspicious("proc:${dir.name}:cmdline", cmdline, runtimeTokens).firstOrNull(),
                matchIfSuspicious("proc:${dir.name}:comm", comm, runtimeTokens).firstOrNull()
            )
        }
    }.getOrDefault(emptyList())
}
```

检测原理：

Frida server、LSPosed daemon、Zygisk/Riru 组件或其他 Hook 服务可能以独立进程存在。读取 `/proc/<pid>/cmdline`、`/proc/<pid>/comm` 和 `ps` 输出可以发现进程名或命令行中的关键词。

实现细节：

- 遍历 `/proc` 下名称全是数字的目录。
- 对每个 pid 读取：
  - `/proc/<pid>/cmdline`
  - `/proc/<pid>/comm`
- 把 `cmdline` 中的空字符替换为空格。
- 用 `runtimeTokens` 匹配。
- 同时执行 `ps -A` 并匹配输出。
- 如果 `ps -A` 没有证据，再执行 `ps` 作为兼容 fallback。

命中证据格式：

```text
proc:1234:cmdline token=frida /data/local/tmp/frida-server
ps -A token=lspd u0_a... lspd
```

注意点：

- Android 8 以后普通 App 对其他进程可见性明显受限。
- 命中是强信号，未命中是弱结论。

### 6.16 ptrace 调试附加状态

检测 ID：`tracer-pid`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:462`

关键代码：

```kotlin
val tracerLine = readLines("/proc/self/status", 200).firstOrNull { it.startsWith("TracerPid:") }
val tracerPid = tracerLine?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
val evidence = if (tracerPid > 0) listOf("TracerPid=$tracerPid") else emptyList()
```

检测原理：

Linux 进程的 `/proc/self/status` 中有 `TracerPid` 字段。值为 `0` 表示没有被 ptrace 附加；非 0 表示当前进程正在被某个进程跟踪。调试器、动态分析器或某些注入工具可能使用 ptrace 附加目标进程。

实现细节：

- 读取 `/proc/self/status`。
- 查找以 `TracerPid:` 开头的行。
- 解析冒号后的整数。
- 如果大于 0，则记录证据。

命中证据格式：

```text
TracerPid=12345
```

注意点：

- 非 0 不一定就是 Frida，也可能是正常调试器。
- 这是当前进程自检，不依赖跨进程权限。

### 6.17 挂载表中的模块痕迹

检测 ID：`mount-info`

代码位置：

- 检测函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:476`

关键代码：

```kotlin
val evidence = matchingLines(
    label = "mountinfo",
    lines = readLines("/proc/self/mountinfo", 5000) + readLines("/proc/mounts", 5000),
    tokens = listOf("magisk", "zygisk", "riru", "lsposed", "lspd", "edxposed", "xposed", "shamiko")
)
```

检测原理：

Magisk、Zygisk、Riru、LSPosed、EdXposed 等模块可能通过 overlay、bind mount 或模块目录挂载影响系统或进程视图。`/proc/self/mountinfo` 和 `/proc/mounts` 里可能留下模块名、目录名或挂载路径痕迹。

实现细节：

- 读取 `/proc/self/mountinfo` 前 5000 行。
- 读取 `/proc/mounts` 前 5000 行。
- 使用模块相关关键词匹配。
- 命中后记录 token 和原始挂载行。

命中证据格式：

```text
mountinfo token=magisk ... /data/adb/modules/...
```

注意点：

- 挂载信息容易被隐藏模块过滤。
- 某些 ROM 或安全工具路径中也可能包含类似关键词。

### 6.18 Native 层自检汇总

检测 ID：`native-scan`

代码位置：

- Kotlin 汇总函数：`app/src/main/java/com/example/envscope/detection/EnvironmentScanner.kt:492`
- Native JNI 入口：`app/src/main/cpp/native-lib.cpp:239`
- Native 总调度：`app/src/main/cpp/native-lib.cpp:221`

关键代码：

```kotlin
private fun checkNative(nativeCollector: () -> List<String>): DetectionCheck {
    val nativeResult = runCatching {
        nativeCollector().map(::compact).filter { it.isNotBlank() }.distinct().take(40)
    }
    return if (nativeResult.isSuccess) {
        check(
            id = "native-scan",
            area = DetectionArea.NATIVE,
            severity = Severity.CRITICAL,
            evidence = nativeResult.getOrDefault(emptyList())
        )
    } else {
        DetectionCheck(
            id = "native-scan",
            area = DetectionArea.NATIVE,
            severity = Severity.INFO,
            hit = false,
            note = "Native 扫描失败：${nativeResult.exceptionOrNull()?.javaClass?.simpleName}"
        )
    }
}
```

```cpp
std::vector<std::string> collectSignals() {
    std::vector<std::string> evidence;
    evidence.reserve(64);

    scanLoadedLibraries(evidence);
    scanExportedSymbols(evidence);
    scanFileForTokens(evidence, "/proc/self/maps", "native maps", 6000);
    scanExecutableMaps(evidence);
    scanThreadNames(evidence);
    scanFileForTokens(evidence, "/proc/net/unix", "native unix socket", 4000);
    scanTcpPorts(evidence);
    scanTracerPid(evidence);

    return evidence;
}
```

检测原理：

Kotlin 层可能被 Hook、反射结果可能被替换，Java API 也可能被拦截。Native 层使用 libc、动态链接器和 `/proc` 直接观察进程状态，可以和 Kotlin 层形成交叉验证。任何 Native 子检测返回证据，Kotlin 的 `native-scan` 就会命中。

实现细节：

- Kotlin 调用 `collectNativeSignals()`。
- Native 收集多个子检测证据。
- Native 返回 `jobjectArray` 字符串数组。
- Kotlin 去重、压缩、限制数量后生成 `DetectionCheck`。
- Native 调用失败不会导致扫描崩溃，而是返回 `INFO` 级未命中项并带失败说明。

## 7. Native 层子检测项

Native 层并没有把每个子检测单独包装成一个 `DetectionCheck`，而是把全部命中证据合并到 Kotlin 的 `native-scan` 检测项中。下面按 C++ 函数说明每个子检测。

### 7.1 Native 公共关键词与证据规整

代码位置：

- `kRuntimeTokens`：`app/src/main/cpp/native-lib.cpp:17`
- `containsToken()`：`app/src/main/cpp/native-lib.cpp:60`
- `addEvidence()`：`app/src/main/cpp/native-lib.cpp:67`
- `compact()`：`app/src/main/cpp/native-lib.cpp:45`

关键代码：

```cpp
const std::vector<std::string> kRuntimeTokens = {
        "frida", "gum-js-loop", "gmain", "gdbus", "linjector",
        "xposed", "lsposed", "lspd", "edxposed", "riru",
        "zygisk", "substrate", "magisk", "shamiko",
        "sandhook", "yahfa", "epic", "whale"
};
```

```cpp
bool containsToken(const std::string& value, const std::vector<std::string>& tokens) {
    const std::string lowered = lower(value);
    return std::any_of(tokens.begin(), tokens.end(), [&](const std::string& token) {
        return lowered.find(token) != std::string::npos;
    });
}
```

```cpp
void addEvidence(std::vector<std::string>& evidence, const std::string& value) {
    if (value.empty()) {
        return;
    }
    const std::string normalized = compact(value);
    if (std::find(evidence.begin(), evidence.end(), normalized) == evidence.end()) {
        evidence.push_back(normalized);
    }
}
```

实现说明：

- Native 层使用与 Kotlin 层相近的运行时关键词。
- `compact()` 会替换空字符、换行、回车、制表符，并把连续双空格压缩。
- 单条 Native 证据长度限制为 260 字符。
- `addEvidence()` 负责去重。

### 7.2 已加载共享库枚举

对应 Native 函数：`scanLoadedLibraries()`

代码位置：

- `app/src/main/cpp/native-lib.cpp:103`

关键代码：

```cpp
void scanLoadedLibraries(std::vector<std::string>& evidence) {
    struct Context {
        std::vector<std::string>* evidence;
    } context{&evidence};

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* context = static_cast<Context*>(data);
        if (info == nullptr || info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
            return 0;
        }
        const std::string name(info->dlpi_name);
        if (containsToken(name, kRuntimeTokens)) {
            addEvidence(*context->evidence, "dl_iterate_phdr: " + name);
        }
        return 0;
    }, &context);
}
```

检测原理：

`dl_iterate_phdr()` 可以枚举当前进程动态链接器已加载的 ELF 对象。若 Frida Gadget、Substrate、Xposed native bridge、Riru/Zygisk 模块或 inline hook 框架以 so 形式加载，库路径或库名可能被枚举出来。

命中证据格式：

```text
dl_iterate_phdr: /data/local/tmp/libfrida-gadget.so
```

### 7.3 导出符号探测

对应 Native 函数：`scanExportedSymbols()`

代码位置：

- `app/src/main/cpp/native-lib.cpp:121`

关键代码：

```cpp
const char* symbols[] = {
        "frida_agent_main",
        "frida_gadget_main",
        "gum_init_embedded",
        "gum_deinit_embedded",
        "gum_interceptor_attach",
        "gum_script_backend_obtain_qjs",
        "gum_script_backend_obtain_v8",
        "xposedCallHandler",
        "MSHookFunction",
        "MSHookMessageEx",
        "Java_de_robv_android_xposed_XposedBridge_hookMethodNative"
};

for (const char* symbol : symbols) {
    if (dlsym(RTLD_DEFAULT, symbol) != nullptr) {
        addEvidence(evidence, std::string("dlsym exported symbol: ") + symbol);
    }
}
```

检测原理：

如果 Frida、Gum、Substrate 或 Xposed 相关 native 符号被导出到当前进程的默认符号查找范围，`dlsym(RTLD_DEFAULT, symbol)` 可以解析到它们。符号命中比单纯路径关键词更直接，说明相关 native 组件已经被加载并暴露符号。

命中证据格式：

```text
dlsym exported symbol: gum_interceptor_attach
```

注意点：

- 很多库会隐藏符号或使用局部符号表，此时 `dlsym()` 可能查不到。
- 命中时属于强进程内证据。

### 7.4 Native `/proc/self/maps` 关键词扫描

对应 Native 函数：`scanFileForTokens()`

代码位置：

- 通用文件扫描函数：`app/src/main/cpp/native-lib.cpp:91`
- 调用位置：`app/src/main/cpp/native-lib.cpp:227`

关键代码：

```cpp
void scanFileForTokens(
        std::vector<std::string>& evidence,
        const char* path,
        const char* label,
        size_t maxLines) {
    for (const std::string& line : readLines(path, maxLines)) {
        if (containsToken(line, kRuntimeTokens)) {
            addEvidence(evidence, std::string(label) + ": " + line);
        }
    }
}
```

```cpp
scanFileForTokens(evidence, "/proc/self/maps", "native maps", 6000);
```

检测原理：

与 Kotlin 的 maps 检测相同，但从 C++ 层读取 `/proc/self/maps`。这可以减少 Java API 被 Hook 后对检测结果的影响。

命中证据格式：

```text
native maps: 7a... /data/local/tmp/libfrida-gadget.so
```

### 7.5 Native 异常 RWX 映射扫描

对应 Native 函数：`scanExecutableMaps()`

代码位置：

- `app/src/main/cpp/native-lib.cpp:208`

关键代码：

```cpp
void scanExecutableMaps(std::vector<std::string>& evidence) {
    for (const std::string& line : readLines("/proc/self/maps", 6000)) {
        const std::string lowered = lower(line);
        if (line.find(" rwxp ") != std::string::npos &&
            lowered.find("/system/") == std::string::npos &&
            lowered.find("/apex/") == std::string::npos &&
            lowered.find("[anon:dalvik") == std::string::npos &&
            lowered.find("jit-cache") == std::string::npos) {
            addEvidence(evidence, "native rwx map: " + line);
        }
    }
}
```

检测原理：

从 Native 层重复检测可写可执行映射。逻辑与 Kotlin 类似，但 C++ 版本通过字符串查找 `" rwxp "`，关注 maps 中典型权限字段。

命中证据格式：

```text
native rwx map: 7a... rwxp ...
```

### 7.6 Native 线程名扫描

对应 Native 函数：`scanThreadNames()`

代码位置：

- `app/src/main/cpp/native-lib.cpp:143`

关键代码：

```cpp
DIR* dir = opendir("/proc/self/task");
...
std::string path = std::string("/proc/self/task/") + entry->d_name + "/comm";
std::ifstream file(path);
std::string name;
if (file.is_open() && std::getline(file, name) && containsToken(name, kRuntimeTokens)) {
    addEvidence(evidence, std::string("native thread: ") + entry->d_name + ":" + name);
}
```

检测原理：

从 Native 层直接枚举 `/proc/self/task` 并读取每个线程的 `comm` 名，查找 Frida/Gum/LSPosed/Riru/Zygisk 等关键词。与 Kotlin 的 `readTaskNames()` 形成重复验证。

命中证据格式：

```text
native thread: 12345:gum-js-loop
```

### 7.7 Native TCP 端口表扫描

对应 Native 函数：`scanTcpPorts()`

代码位置：

- `app/src/main/cpp/native-lib.cpp:170`
- 端口十六进制转换：`app/src/main/cpp/native-lib.cpp:164`

关键代码：

```cpp
std::vector<std::string> ports;
for (int port = 27040; port <= 27050; ++port) {
    ports.push_back(portHex(port));
}
ports.push_back(portHex(23946));

for (const char* path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
    for (const std::string& line : readLines(path, 2000)) {
        std::string upper = line;
        std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) {
            return static_cast<char>(std::toupper(c));
        });
        for (const std::string& port : ports) {
            if (upper.find(port) != std::string::npos) {
                addEvidence(evidence, std::string(path) + " frida-port " + line);
                break;
            }
        }
    }
}
```

检测原理：

从 C++ 层读取 `/proc/net/tcp` 和 `/proc/net/tcp6`，查找 Frida 常见端口的十六进制表示。该实现与 Kotlin 的 `checkProcNetTcp()` 类似，用于交叉验证。

命中证据格式：

```text
/proc/net/tcp frida-port   0: 0100007F:69A2 ...
```

### 7.8 Native Unix Domain Socket 扫描

对应 Native 函数：`scanFileForTokens()`

代码位置：

- 通用文件扫描函数：`app/src/main/cpp/native-lib.cpp:91`
- 调用位置：`app/src/main/cpp/native-lib.cpp:230`

关键代码：

```cpp
scanFileForTokens(evidence, "/proc/net/unix", "native unix socket", 4000);
```

检测原理：

从 Native 层读取 `/proc/net/unix` 并匹配运行时关键词，发现 Frida、Gum、LSPosed、Magisk/Zygisk/Riru 等 socket 名称。

命中证据格式：

```text
native unix socket: 0000000000000000: ... @frida...
```

### 7.9 Native TracerPid 检测

对应 Native 函数：`scanTracerPid()`

代码位置：

- `app/src/main/cpp/native-lib.cpp:193`

关键代码：

```cpp
void scanTracerPid(std::vector<std::string>& evidence) {
    for (const std::string& line : readLines("/proc/self/status", 256)) {
        if (line.rfind("TracerPid:", 0) != 0) {
            continue;
        }
        std::istringstream stream(line.substr(std::strlen("TracerPid:")));
        int tracerPid = 0;
        stream >> tracerPid;
        if (tracerPid > 0) {
            addEvidence(evidence, "native TracerPid=" + std::to_string(tracerPid));
        }
        return;
    }
}
```

检测原理：

与 Kotlin 的 `checkTracerPid()` 相同，从 Native 层读取 `/proc/self/status` 并解析 `TracerPid`。非 0 表示进程被 ptrace 跟踪。

命中证据格式：

```text
native TracerPid=12345
```

## 8. UI 展示逻辑

代码位置：

- `renderReport()`：`app/src/main/java/com/example/envscope/MainActivity.kt:48`
- `createCheckView()`：`app/src/main/java/com/example/envscope/MainActivity.kt:65`

关键代码：

```kotlin
binding.summaryText.text = buildString {
    append("风险等级：${report.riskLabel}\n")
    append("命中 ${report.hits.size}/${report.checks.size} 项，风险分 ${report.riskScore}，耗时 ${report.durationMillis} ms")
}
```

```kotlin
val sortedChecks = report.checks.sortedWith(
    compareByDescending<DetectionCheck> { it.hit }
        .thenByDescending { it.severity.score }
        .thenBy { it.area.label }
        .thenBy { it.title }
)
```

```kotlin
val evidenceText = when {
    check.evidence.isNotEmpty() -> check.evidence.joinToString(separator = "\n") { "• $it" }
    !check.note.isNullOrBlank() -> check.note
    else -> "未发现命中证据。"
}
```

实现说明：

- 顶部展示整体风险等级、命中数量、总检测项数量、风险分、耗时。
- 检测项排序规则：
  - 命中项在前。
  - 严重级别高的在前。
  - 再按检测区域和标题排序。
- 每个检测项显示：
  - 状态：命中/通过
  - 检测区域
  - 严重级别
  - 标题
  - 检测说明
  - 证据列表或未命中说明
- 命中项边框更粗，并按严重级别使用不同颜色。

## 9. 检测能力总结

| 序号 | 检测项 | ID | 实现层 | 主要数据源 | 严重级别 |
| --- | --- | --- | --- | --- | --- |
| 1 | 已安装 Hook/注入管理器包名 | `pkg-known` | Kotlin | `PackageManager.getPackageInfo()` | HIGH |
| 2 | 安装包清单关键词扫描 | `pkg-inventory` | Kotlin | `PackageManager.getInstalledPackages()` | MEDIUM |
| 3 | 运行时可加载 Hook 框架类 | `class-loader` | Kotlin | `Class.forName()` | CRITICAL |
| 4 | 线程调用栈 Hook 痕迹 | `thread-stack` | Kotlin | `Thread.getAllStackTraces()` | HIGH |
| 5 | 线程名关键词 | `thread-name` | Kotlin | Java 线程名、`/proc/self/task/*/comm` | HIGH |
| 6 | 进程 maps 注入库或 memfd | `maps-keywords` | Kotlin | `/proc/self/maps` | CRITICAL |
| 7 | 异常 RWX 内存段 | `maps-rwx` | Kotlin | `/proc/self/maps` | LOW |
| 8 | ClassLoader/DexPath 注入路径 | `classloader-path` | Kotlin | `BaseDexClassLoader.pathList` | HIGH |
| 9 | 环境变量关键词 | `env-vars` | Kotlin | `System.getenv()` | MEDIUM |
| 10 | 常见文件路径 | `known-files` | Kotlin | `File.exists()` | HIGH |
| 11 | 系统属性关键词 | `system-properties` | Kotlin | `SystemProperties.get()`、`getprop` | MEDIUM |
| 12 | Frida 本地端口连接探测 | `frida-ports-connect` | Kotlin | TCP connect | HIGH |
| 13 | `/proc/net/tcp` 端口表 | `proc-net-tcp` | Kotlin | `/proc/net/tcp`、`/proc/net/tcp6` | HIGH |
| 14 | Unix Domain Socket 关键词 | `proc-net-unix` | Kotlin | `/proc/net/unix` | MEDIUM |
| 15 | 进程列表关键词 | `process-list` | Kotlin | `/proc/<pid>`、`ps` | HIGH |
| 16 | ptrace 调试附加状态 | `tracer-pid` | Kotlin | `/proc/self/status` | HIGH |
| 17 | 挂载表模块痕迹 | `mount-info` | Kotlin | `/proc/self/mountinfo`、`/proc/mounts` | MEDIUM |
| 18 | Native 层自检 | `native-scan` | Kotlin + C++ | `dl_iterate_phdr`、`dlsym`、`/proc` | CRITICAL |

## 10. 结果解释建议

- `CRITICAL` 命中通常表示进程内强证据，例如可加载 Hook 类、maps 中存在注入库、Native 层发现相关 so 或符号。
- `HIGH` 命中通常表示高可信环境信号，例如管理器包名、Frida 端口、进程名、线程名、`TracerPid`。
- `MEDIUM` 命中通常是环境或外围信号，例如安装包关键词、系统属性、socket、挂载表。
- `LOW` 命中目前主要是异常 RWX 映射，适合作为辅助判断。
- 单项未命中不能证明环境干净，因为包名、进程、端口、maps、`/proc` 和系统属性都可能被隐藏。
- 单项命中也不一定能直接定性为攻击，应结合证据文本、设备场景、调试状态和其他检测项综合判断。

## 11. 维护与扩展位置

常见扩展方式：

- 新增已知包名：修改 `knownPackages`，位置 `EnvironmentScanner.kt:16`。
- 新增可加载类检测：修改 `classNames`，位置 `EnvironmentScanner.kt:37`。
- 新增落地文件路径：修改 `knownPaths`，位置 `EnvironmentScanner.kt:53`。
- 新增包名关键词：修改 `packageTokens`，位置 `EnvironmentScanner.kt:79`。
- 新增运行时关键词：修改 Kotlin `runtimeTokens` 和 Native `kRuntimeTokens`，位置分别是 `EnvironmentScanner.kt:94` 与 `native-lib.cpp:17`。
- 新增调用栈关键词：修改 `stackTokens`，位置 `EnvironmentScanner.kt:118`。
- 新增端口：修改 `fridaPorts`，位置 `EnvironmentScanner.kt:130`；Native 端口逻辑在 `native-lib.cpp:170`。
- 新增 Kotlin 检测项：在 `EnvironmentScanner.scan()` 中追加 `checks += newCheck()`，并实现返回 `DetectionCheck` 的函数。
- 新增 Native 检测项：在 `collectSignals()` 中追加新的扫描函数，并通过 `addEvidence()` 写入证据。
