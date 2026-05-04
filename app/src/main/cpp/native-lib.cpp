#include <jni.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fstream>
#include <link.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

const std::vector<std::string> kRuntimeTokens = {
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
        "magisk",
        "shamiko",
        "sandhook",
        "yahfa",
        "epic",
        "whale"
};

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string compact(std::string value) {
    for (char& c : value) {
        if (c == '\0' || c == '\n' || c == '\r' || c == '\t') {
            c = ' ';
        }
    }
    while (value.find("  ") != std::string::npos) {
        value.replace(value.find("  "), 2, " ");
    }
    if (value.size() > 260) {
        value = value.substr(0, 257) + "...";
    }
    return value;
}

bool containsToken(const std::string& value, const std::vector<std::string>& tokens) {
    const std::string lowered = lower(value);
    return std::any_of(tokens.begin(), tokens.end(), [&](const std::string& token) {
        return lowered.find(token) != std::string::npos;
    });
}

void addEvidence(std::vector<std::string>& evidence, const std::string& value) {
    if (value.empty()) {
        return;
    }
    const std::string normalized = compact(value);
    if (std::find(evidence.begin(), evidence.end(), normalized) == evidence.end()) {
        evidence.push_back(normalized);
    }
}

std::vector<std::string> readLines(const char* path, size_t maxLines) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    if (!file.is_open()) {
        return lines;
    }

    std::string line;
    while (lines.size() < maxLines && std::getline(file, line)) {
        lines.push_back(line);
    }
    return lines;
}

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

void scanExportedSymbols(std::vector<std::string>& evidence) {
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
}

void scanThreadNames(std::vector<std::string>& evidence) {
    DIR* dir = opendir("/proc/self/task");
    if (dir == nullptr) {
        return;
    }

    dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        std::string path = std::string("/proc/self/task/") + entry->d_name + "/comm";
        std::ifstream file(path);
        std::string name;
        if (file.is_open() && std::getline(file, name) && containsToken(name, kRuntimeTokens)) {
            addEvidence(evidence, std::string("native thread: ") + entry->d_name + ":" + name);
        }
    }
    closedir(dir);
}

std::string portHex(int port) {
    char buffer[8] = {0};
    std::snprintf(buffer, sizeof(buffer), ":%04X", port);
    return std::string(buffer);
}

void scanTcpPorts(std::vector<std::string>& evidence) {
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
}

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

} // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_envscope_MainActivity_collectNativeSignals(JNIEnv* env, jobject) {
    const std::vector<std::string> signals = collectSignals();
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray result = env->NewObjectArray(
            static_cast<jsize>(signals.size()),
            stringClass,
            nullptr);

    for (size_t i = 0; i < signals.size(); ++i) {
        jstring value = env->NewStringUTF(signals[i].c_str());
        env->SetObjectArrayElement(result, static_cast<jsize>(i), value);
        env->DeleteLocalRef(value);
    }

    return result;
}
