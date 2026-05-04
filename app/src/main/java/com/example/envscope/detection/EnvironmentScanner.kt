package com.example.envscope.detection

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import java.util.Locale

object EnvironmentScanner {
    private data class KnownPackage(val packageName: String, val label: String)

    private val knownPackages = listOf(
        KnownPackage("de.robv.android.xposed.installer", "Xposed Installer"),
        KnownPackage("de.robv.android.xposed.installer.debug", "Xposed Installer Debug"),
        KnownPackage("org.meowcat.edxposed.manager", "EdXposed Manager"),
        KnownPackage("com.solohsu.android.edxp.manager", "EdXposed Manager"),
        KnownPackage("com.elderdrivers.riru.edxp.manager", "Riru EdXposed Manager"),
        KnownPackage("org.lsposed.manager", "LSPosed Manager"),
        KnownPackage("org.lsposed.lspatch", "LSPatch"),
        KnownPackage("me.weishu.exp", "TaiChi"),
        KnownPackage("me.weishu.exposed", "VirtualXposed/TaiChi"),
        KnownPackage("io.va.exposed", "VirtualXposed"),
        KnownPackage("com.saurik.substrate", "Cydia Substrate"),
        KnownPackage("com.saurik.substrate.safemode", "Cydia Substrate Safemode"),
        KnownPackage("com.topjohnwu.magisk", "Magisk"),
        KnownPackage("io.github.huskydg.magisk", "Kitsune Mask/Magisk fork"),
        KnownPackage("re.frida.server", "Frida server package"),
        KnownPackage("com.frida.server", "Frida server package"),
        KnownPackage("re.frida.gadget", "Frida Gadget package"),
        KnownPackage("com.frida.gadget", "Frida Gadget package")
    )

    private val classNames = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.XC_MethodHook",
        "de.robv.android.xposed.callbacks.XC_LoadPackage",
        "org.lsposed.lspd.impl.LSPosedBridge",
        "org.lsposed.lspd.impl.LSPosedContext",
        "org.lsposed.lspd.service.ILSPApplicationService",
        "com.elderdrivers.riru.edxp._hooker.impl.XposedBridge",
        "com.saurik.substrate.MS",
        "com.saurik.substrate.MS\$MethodPointer",
        "re.frida.Gadget",
        "com.frida.Gadget",
        "frida.Agent"
    )

    private val knownPaths = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/bin/app_process_xposed",
        "/system/bin/app_process32_xposed",
        "/system/bin/app_process64_xposed",
        "/system/xposed.prop",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/lib/libsubstrate.so",
        "/system/lib64/libsubstrate.so",
        "/data/adb/lspd",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/data/adb/modules/edxposed",
        "/data/adb/modules/riru_edxposed",
        "/data/adb/modules/riru-core",
        "/data/adb/modules/zygisk_shamiko",
        "/sbin/.magisk/modules/zygisk_lsposed",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/libfrida-gadget.so",
        "/system/bin/frida-server",
        "/system/xbin/frida-server"
    )

    private val packageTokens = listOf(
        "frida",
        "xposed",
        "lsposed",
        "lspd",
        "edxposed",
        "riru",
        "zygisk",
        "substrate",
        "taichi",
        "virtualxposed",
        "lspatch",
        "magisk"
    )

    private val runtimeTokens = listOf(
        "frida",
        "gum-js-loop",
        "gmain",
        "gdbus",
        "linjector",
        "xposed",
        "lsposed",
        "lspd",
        "edxposed",
        "riru",
        "zygisk",
        "substrate",
        "taichi",
        "virtualxposed",
        "lspatch",
        "magisk",
        "shamiko",
        "sandhook",
        "yahfa",
        "epic",
        "whale"
    )

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

    private val fridaPorts = (27040..27050).toList() + listOf(23946)

    fun scan(context: Context, nativeCollector: () -> List<String>): ScanReport {
        val startedAt = System.currentTimeMillis()
        val appContext = context.applicationContext
        val checks = mutableListOf<DetectionCheck>()

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

        val finishedAt = System.currentTimeMillis()
        return ScanReport(startedAt, finishedAt, checks)
    }

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
            title = "已安装 Hook/注入管理器包名",
            detail = "通过 PackageManager 查询常见 Xposed、LSPosed、EdXposed、Substrate、Magisk、Frida 相关包名。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

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
        return check(
            id = "pkg-inventory",
            area = DetectionArea.SYSTEM,
            title = "安装包清单关键词扫描",
            detail = "枚举可见安装包的包名、标签和 APK 路径，查找 Hook 框架、注入器、Zygisk/Riru 模块相关关键词。",
            severity = Severity.MEDIUM,
            evidence = evidence
        )
    }

    private fun checkClassLoader(context: Context): DetectionCheck {
        val loaders = listOfNotNull(
            context.classLoader,
            Thread.currentThread().contextClassLoader,
            ClassLoader.getSystemClassLoader()
        ).distinct()
        val evidence = mutableListOf<String>()
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
        return check(
            id = "class-loader",
            area = DetectionArea.XPOSED,
            title = "运行时可加载 Hook 框架类",
            detail = "尝试加载 XposedBridge、XposedHelpers、LSPosed、Substrate、Frida Gadget 等典型类名。",
            severity = Severity.CRITICAL,
            evidence = evidence
        )
    }

    private fun checkThreadStacks(): DetectionCheck {
        val evidence = Thread.getAllStackTraces().flatMap { (thread, stackTrace) ->
            stackTrace.mapNotNull { frame ->
                val value = "${thread.name}: ${frame.className}.${frame.methodName}(${frame.fileName}:${frame.lineNumber})"
                val lower = value.lowercase(Locale.US)
                if (stackTokens.any { lower.contains(it) }) compact(value) else null
            }
        }
        return check(
            id = "thread-stack",
            area = DetectionArea.PROCESS,
            title = "线程调用栈 Hook 痕迹",
            detail = "扫描当前进程所有 Java 线程栈，查找 XposedBridge.handleHookedMethod、LSPosed、Substrate、Frida 等痕迹。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkThreadNames(): DetectionCheck {
        val javaThreads = Thread.getAllStackTraces().keys.map { "java:${it.name}" }
        val nativeThreads = readTaskNames().map { "native:$it" }
        val evidence = (javaThreads + nativeThreads).mapNotNull { name ->
            val lower = name.lowercase(Locale.US)
            if (runtimeTokens.any { lower.contains(it) }) compact(name) else null
        }
        return check(
            id = "thread-name",
            area = DetectionArea.FRIDA,
            title = "线程名关键词",
            detail = "检查 Java 线程与 /proc/self/task/*/comm，覆盖 Frida 常见 gum-js-loop、gmain、gdbus、linjector 线程名。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkSelfMaps(): DetectionCheck {
        val evidence = matchingLines(
            label = "/proc/self/maps",
            lines = readLines("/proc/self/maps", 6000),
            tokens = runtimeTokens
        )
        return check(
            id = "maps-keywords",
            area = DetectionArea.FRIDA,
            title = "进程 maps 中的注入库或 memfd",
            detail = "读取 /proc/self/maps，扫描 libfrida-gadget、frida-agent、libxposed、lspd、riru、zygisk、substrate、inline hook 框架等关键词。",
            severity = Severity.CRITICAL,
            evidence = evidence
        )
    }

    private fun checkExecutableMaps(): DetectionCheck {
        val evidence = readLines("/proc/self/maps", 6000).mapNotNull { line ->
            val parts = line.trim().split(Regex("\\s+"))
            val perms = parts.getOrNull(1).orEmpty()
            val lower = line.lowercase(Locale.US)
            val suspicious = perms.startsWith("rwx") &&
                !lower.contains("/system/") &&
                !lower.contains("/apex/") &&
                !lower.contains("[anon:dalvik") &&
                !lower.contains("/memfd:jit-cache")
            if (suspicious) compact(line) else null
        }
        return check(
            id = "maps-rwx",
            area = DetectionArea.PROCESS,
            title = "异常可写可执行内存段",
            detail = "查找当前进程中同时具备写入和执行权限的非系统映射，作为动态插桩或 inline hook 的辅助信号。",
            severity = Severity.LOW,
            evidence = evidence
        )
    }

    private fun checkClassLoaderPaths(context: Context): DetectionCheck {
        val evidence = mutableListOf<String>()
        evidence += matchIfSuspicious("application source", context.applicationInfo.sourceDir, runtimeTokens)
        evidence += matchIfSuspicious("native library dir", context.applicationInfo.nativeLibraryDir, runtimeTokens)
        evidence += inspectClassLoaderPathList(context.classLoader)
        return check(
            id = "classloader-path",
            area = DetectionArea.XPOSED,
            title = "ClassLoader/DexPath 注入路径",
            detail = "反射检查 BaseDexClassLoader 的 dexElements、nativeLibraryDirectories 与 nativeLibraryPathElements 是否带有 Hook/注入关键词。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkEnvironmentVariables(): DetectionCheck {
        val evidence = System.getenv().mapNotNull { (key, value) ->
            val probe = "$key=$value"
            val lower = probe.lowercase(Locale.US)
            if (runtimeTokens.any { lower.contains(it) }) compact(probe) else null
        }
        return check(
            id = "env-vars",
            area = DetectionArea.SYSTEM,
            title = "环境变量关键词",
            detail = "扫描 LD_PRELOAD、CLASSPATH 以及全部可见环境变量，查找 XposedBridge、Frida、Substrate 等注入痕迹。",
            severity = Severity.MEDIUM,
            evidence = evidence
        )
    }

    private fun checkKnownFiles(): DetectionCheck {
        val evidence = knownPaths.mapNotNull { path ->
            val file = File(path)
            if (runCatching { file.exists() }.getOrDefault(false)) {
                compact("$path readable=${file.canRead()} directory=${file.isDirectory}")
            } else {
                null
            }
        }
        return check(
            id = "known-files",
            area = DetectionArea.SYSTEM,
            title = "常见框架与服务文件路径",
            detail = "检查 XposedBridge.jar、app_process_xposed、LSPosed/EdXposed/Riru/Zygisk 模块目录、Frida server/Gadget 常见落点。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkSystemProperties(): DetectionCheck {
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
        val evidence = mutableListOf<String>()
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
        return check(
            id = "system-properties",
            area = DetectionArea.SYSTEM,
            title = "系统属性关键词",
            detail = "读取关键 SystemProperties 并解析 getprop 输出，查找 Xposed、LSPosed、EdXposed、Riru、Zygisk、Magisk、Frida 相关属性。",
            severity = Severity.MEDIUM,
            evidence = evidence
        )
    }

    private fun checkLocalhostPorts(): DetectionCheck {
        val hosts = listOf("127.0.0.1", "::1")
        val evidence = mutableListOf<String>()
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
        return check(
            id = "frida-ports-connect",
            area = DetectionArea.FRIDA,
            title = "Frida 本地端口连接探测",
            detail = "主动探测 127.0.0.1/::1 上 Frida 默认端口 27042、27043 及邻近常见端口。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkProcNetTcp(): DetectionCheck {
        val hexPorts = fridaPorts.map { "%04X".format(Locale.US, it) }.toSet()
        val evidence = (readLines("/proc/net/tcp", 2000) + readLines("/proc/net/tcp6", 2000)).mapNotNull { line ->
            val upper = line.uppercase(Locale.US)
            val match = hexPorts.firstOrNull { upper.contains(":$it") } ?: return@mapNotNull null
            compact("port=0x$match $line")
        }
        return check(
            id = "proc-net-tcp",
            area = DetectionArea.FRIDA,
            title = "/proc/net/tcp 端口表",
            detail = "解析 /proc/net/tcp 与 tcp6，查找 Frida server 常用端口是否处于监听或连接状态。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkProcNetUnix(): DetectionCheck {
        val evidence = matchingLines(
            label = "/proc/net/unix",
            lines = readLines("/proc/net/unix", 4000),
            tokens = runtimeTokens
        )
        return check(
            id = "proc-net-unix",
            area = DetectionArea.FRIDA,
            title = "Unix Domain Socket 关键词",
            detail = "扫描 /proc/net/unix，查找 Frida、gum、LSPosed、LSP、Magisk/Zygisk/Riru 等 socket 名称。",
            severity = Severity.MEDIUM,
            evidence = evidence
        )
    }

    private fun checkProcesses(): DetectionCheck {
        val evidence = mutableListOf<String>()
        evidence += scanProcProcesses()
        evidence += matchingLines("ps -A", runCommand(listOf("ps", "-A"), 1800), runtimeTokens)
        if (evidence.isEmpty()) {
            evidence += matchingLines("ps", runCommand(listOf("ps"), 1800), runtimeTokens)
        }
        return check(
            id = "process-list",
            area = DetectionArea.PROCESS,
            title = "进程列表关键词",
            detail = "尝试读取 /proc/[pid]/cmdline、/proc/[pid]/comm 以及 ps 输出，查找 frida-server、lspd、zygisk、riru、xposed 等进程。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkTracerPid(): DetectionCheck {
        val tracerLine = readLines("/proc/self/status", 200).firstOrNull { it.startsWith("TracerPid:") }
        val tracerPid = tracerLine?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
        val evidence = if (tracerPid > 0) listOf("TracerPid=$tracerPid") else emptyList()
        return check(
            id = "tracer-pid",
            area = DetectionArea.PROCESS,
            title = "ptrace 调试附加状态",
            detail = "读取 /proc/self/status 的 TracerPid，发现非 0 表示当前进程被调试器或插桩器 ptrace 附加。",
            severity = Severity.HIGH,
            evidence = evidence
        )
    }

    private fun checkMountInfo(): DetectionCheck {
        val evidence = matchingLines(
            label = "mountinfo",
            lines = readLines("/proc/self/mountinfo", 5000) + readLines("/proc/mounts", 5000),
            tokens = listOf("magisk", "zygisk", "riru", "lsposed", "lspd", "edxposed", "xposed", "shamiko")
        )
        return check(
            id = "mount-info",
            area = DetectionArea.SYSTEM,
            title = "挂载表中的模块痕迹",
            detail = "扫描 mountinfo 与 mounts，查找 Magisk、Zygisk、Riru、LSPosed/EdXposed 等模块挂载痕迹。",
            severity = Severity.MEDIUM,
            evidence = evidence
        )
    }

    private fun checkNative(nativeCollector: () -> List<String>): DetectionCheck {
        val nativeResult = runCatching {
            nativeCollector().map(::compact).filter { it.isNotBlank() }.distinct().take(40)
        }
        return if (nativeResult.isSuccess) {
            check(
                id = "native-scan",
                area = DetectionArea.NATIVE,
                title = "Native 层自检",
                detail = "C++ 层使用 dl_iterate_phdr、dlsym、/proc/self/maps、/proc/self/task、/proc/net/tcp/unix 和 TracerPid 做交叉扫描。",
                severity = Severity.CRITICAL,
                evidence = nativeResult.getOrDefault(emptyList())
            )
        } else {
            DetectionCheck(
                id = "native-scan",
                area = DetectionArea.NATIVE,
                title = "Native 层自检",
                detail = "C++ 层使用 dl_iterate_phdr、dlsym、/proc/self/maps、/proc/self/task、/proc/net/tcp/unix 和 TracerPid 做交叉扫描。",
                severity = Severity.INFO,
                hit = false,
                note = "Native 扫描失败：${nativeResult.exceptionOrNull()?.javaClass?.simpleName}"
            )
        }
    }

    private fun check(
        id: String,
        area: DetectionArea,
        title: String,
        detail: String,
        severity: Severity,
        evidence: List<String>
    ): DetectionCheck {
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

    private fun findPackage(pm: PackageManager, packageName: String): PackageInfo? {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
        }.getOrNull()
    }

    private fun installedPackages(pm: PackageManager): List<PackageInfo> {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
        }.getOrDefault(emptyList())
    }

    private fun inspectClassLoaderPathList(loader: ClassLoader): List<String> {
        val evidence = mutableListOf<String>()
        var clazz: Class<*>? = loader.javaClass
        while (clazz != null) {
            val currentClazz = clazz
            val pathList = runCatching {
                currentClazz.getDeclaredField("pathList").apply { isAccessible = true }.get(loader)
            }.getOrNull()
            if (pathList != null) {
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
                break
            }
            clazz = currentClazz.superclass
        }
        return evidence
    }

    private fun readTaskNames(): List<String> {
        val taskDir = File("/proc/self/task")
        return runCatching {
            taskDir.listFiles().orEmpty().mapNotNull { task ->
                val comm = File(task, "comm").readTextOrEmpty().trim()
                if (comm.isBlank()) null else "${task.name}:$comm"
            }
        }.getOrDefault(emptyList())
    }

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

    private fun matchingLines(label: String, lines: List<String>, tokens: List<String>): List<String> {
        return lines.mapNotNull { line ->
            val lower = line.lowercase(Locale.US)
            val token = tokens.firstOrNull { lower.contains(it) } ?: return@mapNotNull null
            compact("$label token=$token $line")
        }.distinct().take(30)
    }

    private fun matchIfSuspicious(label: String, value: String?, tokens: List<String>): List<String> {
        if (value.isNullOrBlank()) return emptyList()
        val lower = value.lowercase(Locale.US)
        val token = tokens.firstOrNull { lower.contains(it) } ?: return emptyList()
        return listOf(compact("$label token=$token $value"))
    }

    private fun readLines(path: String, maxLines: Int): List<String> {
        return runCatching {
            File(path).bufferedReader().useLines { sequence ->
                sequence.take(maxLines).toList()
            }
        }.getOrDefault(emptyList())
    }

    private fun File.readTextOrEmpty(): String {
        return runCatching { readText() }.getOrDefault("")
    }

    private fun getSystemProperty(key: String): String {
        return runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getDeclaredMethod("get", String::class.java)
            method.invoke(null, key) as? String
        }.getOrNull().orEmpty()
    }

    private fun runCommand(command: List<String>, timeoutMillis: Long): List<String> {
        val lines = Collections.synchronizedList(mutableListOf<String>())
        val process = runCatching {
            ProcessBuilder(command).redirectErrorStream(true).start()
        }.getOrNull() ?: return emptyList()
        val reader = Thread {
            runCatching {
                process.inputStream.bufferedReader().useLines { sequence ->
                    sequence.take(2500).forEach { lines += it }
                }
            }
        }
        reader.start()
        runCatching { reader.join(timeoutMillis) }
        if (reader.isAlive) {
            runCatching { process.destroy() }
        }
        return synchronized(lines) { lines.toList() }
    }

    private fun compact(value: String): String {
        val normalized = value.replace('\u0000', ' ').replace(Regex("\\s+"), " ").trim()
        return if (normalized.length > 240) normalized.take(237) + "..." else normalized
    }
}
