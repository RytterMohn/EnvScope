# EnvScope

Language: English | [Chinese](README.zh-CN.md)

EnvScope is an Android runtime inspection app for detecting Frida, Xposed, LSPosed, EdXposed, Substrate, Riru, Zygisk/Magisk, and related dynamic instrumentation or hook traces.

The project combines Kotlin-side and native C++ checks. The Kotlin layer inspects packages, class loading, thread stacks, environment variables, system properties, ports, processes, and mount tables. The native layer cross-checks loaded shared libraries, exported symbols, `/proc`, thread names, sockets, and `TracerPid`.

## Build

This project uses Android Gradle Plugin 8.7.1, Kotlin 1.9.24, and compileSdk 35.

```powershell
$env:JAVA_HOME='C:\Users\11980\AppData\Local\Programs\Android Studio\jbr'
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
.\gradlew.bat assembleDebug
```

Debug APK output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

## Permissions

- `android.permission.INTERNET`: used to actively probe common Frida ports on `127.0.0.1` and `::1`.
- `android.permission.QUERY_ALL_PACKAGES`: used to enumerate installed packages and inspect package names or paths related to hook managers, Frida Gadget, Magisk, and LSPosed. This permission is suitable for security self-checking, internal distribution, or research use. If published to an app store, its usage must follow the platform policy.
- `<queries>`: declares common Xposed, LSPosed, EdXposed, Substrate, Magisk, and Frida package names to improve package visibility on Android 11 and later.

## Detection Points

### 1. Known Hook or Injection Manager Packages

Uses `PackageManager.getPackageInfo()` to query common package names:

- Xposed Installer: `de.robv.android.xposed.installer`
- LSPosed: `org.lsposed.manager`
- EdXposed: `org.meowcat.edxposed.manager`, `com.solohsu.android.edxp.manager`
- Riru EdXposed: `com.elderdrivers.riru.edxp.manager`
- LSPatch: `org.lsposed.lspatch`
- TaiChi / VirtualXposed: `me.weishu.exp`, `me.weishu.exposed`, `io.va.exposed`
- Cydia Substrate: `com.saurik.substrate`
- Magisk / Kitsune Mask: `com.topjohnwu.magisk`, `io.github.huskydg.magisk`
- Frida-related packages: `re.frida.server`, `com.frida.server`, `re.frida.gadget`, `com.frida.gadget`

### 2. Installed Package Inventory Keyword Scan

Enumerates visible installed packages and scans package names, application labels, and APK paths for:

```text
frida, xposed, lsposed, lspd, edxposed, riru, zygisk,
substrate, taichi, virtualxposed, lspatch, magisk
```

This can reveal renamed builds, forked versions, or module managers that are not covered by the exact package-name list.

### 3. Runtime-Loadable Hook Framework Classes

Attempts to load typical hook and instrumentation classes through the current `ClassLoader`, the thread context `ClassLoader`, and the system `ClassLoader`:

- `de.robv.android.xposed.XposedBridge`
- `de.robv.android.xposed.XposedHelpers`
- `de.robv.android.xposed.XC_MethodHook`
- `de.robv.android.xposed.callbacks.XC_LoadPackage`
- `org.lsposed.lspd.impl.LSPosedBridge`
- `org.lsposed.lspd.impl.LSPosedContext`
- `com.saurik.substrate.MS`
- `re.frida.Gadget`, `com.frida.Gadget`, `frida.Agent`

If these classes can be loaded, the process likely contains a hook framework or a Gadget-style injection environment.

### 4. Hook Traces in Thread Stacks

Scans all Java thread stack traces in the current process for:

```text
xposedbridge, xposedhelpers, handlehookedmethod,
invokeoriginalmethodnative, lsposed, lspd, edxposed,
substrate, frida
```

This helps identify Xposed/LSPosed hook call chains, original-method bridge calls, or Frida-related stack frames.

### 5. Thread Name Keywords

Checks Java thread names and `/proc/self/task/*/comm`, including common Frida thread names:

- `gum-js-loop`
- `gmain`
- `gdbus`
- `pool-frida`
- `linjector`

It also matches keywords such as `xposed`, `lsposed`, `lspd`, `riru`, and `zygisk`.

### 6. Injected Libraries or memfd Entries in `/proc/self/maps`

Reads the current process maps and searches for:

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

This can reveal loaded native injection libraries, memory-file mappings, inline hook frameworks, or Zygisk/Riru-related shared objects.

### 7. Suspicious Writable and Executable Memory

Scans maps for non-system, non-APEX, non-standard ART JIT `rwx` mappings. This is not Frida/Xposed-specific evidence, but it is useful as an auxiliary signal for dynamic instrumentation, shellcode, or inline hooks.

### 8. ClassLoader / DexPath Injection Paths

Reflectively inspects `BaseDexClassLoader` internals:

- `dexElements`
- `nativeLibraryDirectories`
- `nativeLibraryPathElements`

If dex, apk, jar, or shared-library paths contain Frida, Xposed, LSPosed, LSPatch, Substrate, Riru, or Zygisk keywords, the check is marked as a hit.

### 9. Environment Variable Keywords

Scans `System.getenv()`, with special attention to:

- `LD_PRELOAD`
- `CLASSPATH`
- Custom environment variables added by injection frameworks

The check is marked as a hit if environment variables contain keywords such as `XposedBridge.jar`, `frida`, or `substrate`.

### 10. Common Framework and Service File Paths

Checks common file locations:

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

Android sandboxing may restrict access to some paths. This check is useful as positive evidence, but a miss should not be treated as proof that the environment is clean.

### 11. System Property Keywords

Uses reflection on `android.os.SystemProperties.get()` and parses `getprop` output to scan properties such as:

- `persist.sys.xposed`
- `persist.sys.taichi`
- `ro.dalvik.vm.native.bridge`
- `ro.boot.zygisk`
- `persist.zygisk.enabled`
- `ro.magisk.version`
- `ro.lsposed.version`
- `ro.edxposed.version`

The full `getprop` output is also keyword-matched.

### 12. Frida Local Port Probing

Actively connects to:

- `127.0.0.1`
- `::1`

Port range:

- `27040` through `27050`
- `23946`

Ports `27042` and `27043` are common Frida server defaults. Open ports in this range are marked as high risk.

### 13. `/proc/net/tcp` Port Table

Reads `/proc/net/tcp` and `/proc/net/tcp6`, then searches for the hexadecimal representation of common Frida ports. This covers cases where active connection probing fails but the port table is still visible.

### 14. Unix Domain Socket Keywords

Scans `/proc/net/unix` for socket names related to Frida, gum, LSPosed, LSP, Magisk, Zygisk, and Riru.

### 15. Process List Keywords

Reads:

- `/proc/[pid]/cmdline`
- `/proc/[pid]/comm`
- `ps -A`
- `ps`

Searches for process names or command lines such as `frida-server`, `lspd`, `zygisk`, `riru`, and `xposed`. Android 8 and later restrict cross-process visibility, so this check is strong when it hits and weak when it misses.

### 16. `TracerPid` Debug Attach State

Reads `TracerPid` from `/proc/self/status`. A non-zero value means the current process is attached with `ptrace`, which may indicate a debugger, Frida, or another dynamic analysis tool.

### 17. Module Traces in Mount Tables

Scans:

- `/proc/self/mountinfo`
- `/proc/mounts`

Searches for module traces such as `magisk`, `zygisk`, `riru`, `lsposed`, `lspd`, `edxposed`, `xposed`, and `shamiko`.

### 18. Native Self-Inspection

The C++ layer performs independent checks:

- Uses `dl_iterate_phdr` to enumerate loaded shared libraries and search for Frida/Xposed/LSPosed/Riru/Zygisk/Substrate keywords.
- Uses `dlsym(RTLD_DEFAULT, ...)` to search for exported symbols such as `frida_agent_main`, `gum_interceptor_attach`, `MSHookFunction`, and `xposedCallHandler`.
- Reads `/proc/self/maps` for a second maps scan from the native layer.
- Reads `/proc/self/task/*/comm` for native-side thread name scanning.
- Reads `/proc/net/tcp` and `/proc/net/tcp6` for common Frida ports.
- Reads `/proc/net/unix` for injection-framework sockets.
- Reads `/proc/self/status` to check `TracerPid`.

The native layer complements the Kotlin layer when Java APIs are hooked, replaced, or restricted.

## Risk Levels

The app accumulates a risk score from matched checks:

- `Critical`: strong in-process evidence such as loaded classes, maps entries, native shared libraries, or exported symbols.
- `High`: high-confidence signals such as ports, processes, threads, file paths, or debug attachment.
- `Medium`: environmental signals such as system properties, package inventory, sockets, or mount tables.
- `Low`: auxiliary signals such as writable and executable memory mappings.

## Limitations

- Frida, LSPosed, Magisk/Zygisk, and similar tools can hide package names, processes, ports, maps entries, or `/proc` content. Any single detection point can be bypassed.
- Android version, ROM behavior, SELinux policy, app sandboxing, and package visibility rules can affect file, process, socket, and package enumeration results.
- Keyword-based checks may produce false positives, for example when security tools, debugging tools, or internal modules use similar names or paths.
- EnvScope results should be treated as a multi-signal assessment, not as a decision based on one check.
