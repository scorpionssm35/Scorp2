#include "VulkanDetector.h"
#include "LogUtils.h"
#include "dllmain.h"
#include <wintrust.h>
#include <softpub.h>
#include <algorithm>
#include "DetectionAggregator.h"
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
VulkanDetector::VulkanDetector() {
    // Конструктор
}
VulkanDetector::~VulkanDetector() {
    Stop();
}
bool VulkanDetector::Initialize() {
    if (m_initialized) return true;

    try {
        Logs(VulkanLogLevel::INFO, "Initializing Vulkan detector...");

        // Инициализируем список функций для мониторинга
        InitializeFunctionList();

        // Первичное сканирование модулей
        ScanVulkanModules();

        m_initialized = true;
        Logs(VulkanLogLevel::INFO, "Vulkan detector initialized. Monitoring " +
            std::to_string(m_monitoredFunctions.size()) + " functions");
        return true;
    }
    catch (const std::exception& e) {
        Logs(VulkanLogLevel::WARNING, std::string("Exception during initialization: ") + e.what());
        return false;
    }
    catch (...) {
        Logs(VulkanLogLevel::WARNING, "Exception during initialization");
        return false;
    }
}
bool VulkanDetector::Start() {
    if (m_isRunning.exchange(true)) {
        return true;
    }

    if (!m_initialized && !Initialize()) {
        m_isRunning = false;
        return false;
    }

    try {
        m_detectionThread = std::thread(&VulkanDetector::DetectionLoop, this);
        Logs(VulkanLogLevel::INFO, "Vulkan detector started");
        return true;
    }
    catch (const std::exception& e) {
        Logs(VulkanLogLevel::WARNING, std::string("Failed to start thread: ") + e.what());
        m_isRunning = false;
        return false;
    }
}
void VulkanDetector::Stop() {
    if (!m_isRunning.exchange(false)) return;

    Logs(VulkanLogLevel::INFO, "Stopping Vulkan detector...");

    if (m_detectionThread.joinable()) {
        m_detectionThread.join();
    }

    Logs(VulkanLogLevel::INFO, "Vulkan detector stopped");
}
void VulkanDetector::SetConfig(const VulkanDetectorConfig& config) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_config = config;
}
uint64_t VulkanDetector::GetTickMs() {
    return GetTickCount64();
}
bool VulkanDetector::ShouldLog(const std::string& key, uint64_t cooldownMs) {
    uint64_t now = GetTickMs();

    std::lock_guard<std::mutex> lock(m_dataMutex);

    // УБИРАЕМ автоматическую очистку здесь - теперь она только в главном цикле
    auto it = m_lastLogTime.find(key);
    if (it == m_lastLogTime.end() || now - it->second > cooldownMs) {
        m_lastLogTime[key] = now;
        return true;
    }
    return false;
}
void VulkanDetector::Logs(VulkanLogLevel level, const std::string& message) {
    std::string prefix;
    uint64_t cooldown = 1000;

    switch (level) {
    case VulkanLogLevel::DETECTION:
        prefix = "[VEH] ";
        cooldown = 5000;
        break;
    case VulkanLogLevel::WARNING:
        prefix = "[LOGEN] [VulkanWarn] ";
        cooldown = 10000;
        break;
    default:
        prefix = "[LOGEN] [Vulkan] ";
        cooldown = 5000;
        break;
    }

    if (ShouldLog(message, cooldown)) {
        Log((prefix + message).c_str());

        if (level == VulkanLogLevel::DETECTION && m_config.enableScreenshotOnDetection) {
            StartSightImgDetection("[VEH] Vulkan: " + message);
        }
    }
}
std::string VulkanDetector::GetModuleHash(const std::string& path) {
    if (path.empty() || path == "unknown") {
        return "";
    }
    return CalculateFileSHA256Safe(path);
}
bool VulkanDetector::IsModuleWhitelisted(const std::string& name, const std::string& path) {
    std::string lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    for (const auto& whitelisted : m_config.whitelistedModules) {
        std::string lowerWhitelisted = whitelisted;
        std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(),
            lowerWhitelisted.begin(), ::tolower);
        if (lowerName == lowerWhitelisted) {
            return true;
        }
    }

    return IsSystemPath(path);
}
bool VulkanDetector::IsSystemPath(const std::string& path) {
    std::string lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    for (const auto& sysPath : m_config.whitelistedPaths) {
        if (lowerPath.find(sysPath) != std::string::npos) {
            return true;
        }
    }
    return false;
}
bool VulkanDetector::CheckDigitalSignature(const std::string& path) {
    if (path.empty()) return false;

    int wchars_needed = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, NULL, 0);
    std::wstring wpath(wchars_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wchars_needed);

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wpath.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(NULL, &policyGuid, &trustData);
    return status == ERROR_SUCCESS;
}
bool VulkanDetector::SafeReadMemory(uintptr_t address, void* buffer, size_t size) {
    if (!address || address < 0x10000 || address > 0x7FFFFFFFFFFF) return false;

    // Проверяем доступность памяти
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == 0) return false;

    if (!(mbi.State == MEM_COMMIT &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))) {
        return false;
    }

    __try {
        memcpy(buffer, (void*)address, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
std::string VulkanDetector::GetModuleByAddress(uintptr_t address, std::string& fullPath) {
    fullPath = "unknown";

    try {
        HMODULE hMods[256];
        DWORD cbNeeded;
        HANDLE hProcess = GetCurrentProcess();

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
                    uintptr_t end = base + modInfo.SizeOfImage;

                    if (address >= base && address < end) {
                        char modName[MAX_PATH];
                        if (GetModuleBaseNameA(hProcess, hMods[i], modName, MAX_PATH)) {
                            char modPath[MAX_PATH];
                            if (GetModuleFileNameExA(hProcess, hMods[i], modPath, MAX_PATH)) {
                                fullPath = modPath;
                                return std::string(modName);
                            }
                        }
                    }
                }
            }
        }
    }
    catch (...) {
        // Игнорируем
    }

    return "unknown";
}
std::string VulkanDetector::AnalyzeHookType(uint8_t* bytes, size_t size) {
    if (size < 5) return "UNKNOWN";

    if (bytes[0] == 0xE9) {
        return "JMP_REL32";
    }

    if (size >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25) {
        return "JMP_RIP_RELATIVE";
    }

    if (bytes[0] == 0xE8) {
        return "CALL_REL32";
    }

    if (size >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 &&
        bytes[10] == 0xFF && bytes[11] == 0xE0) {
        return "MOV_RAX_JMP_RAX";
    }

    if (size >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3) {
        return "PUSH_RET";
    }

    if (bytes[0] == 0xCC) {
        return "INT3_BREAKPOINT";
    }

    return "UNKNOWN_PATCH";
}
uintptr_t VulkanDetector::CalculateHookTarget(uintptr_t functionAddr, uint8_t* bytes, size_t size) {
    if (size < 5) return 0;

    if (bytes[0] == 0xE9) {
        int32_t offset = *(int32_t*)(bytes + 1);
        return functionAddr + 5 + offset;
    }

    if (size >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25) {
        int32_t offset = *(int32_t*)(bytes + 2);
        uintptr_t addrPtr = functionAddr + 6 + offset;
        uintptr_t target = 0;
        if (SafeReadMemory(addrPtr, &target, sizeof(target))) {
            return target;
        }
    }

    if (bytes[0] == 0xE8) {
        int32_t offset = *(int32_t*)(bytes + 1);
        return functionAddr + 5 + offset;
    }

    if (size >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8) {
        return *(uintptr_t*)(bytes + 2);
    }

    if (size >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3) {
        return *(uintptr_t*)(bytes + 1);
    }

    return 0;
}
void VulkanDetector::ScanVulkanModules() {
    std::vector<VulkanModuleInfo> newModules;

    try {
        HMODULE hMods[256];
        DWORD cbNeeded;
        HANDLE hProcess = GetCurrentProcess();

        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            return;
        }

        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH] = { 0 };
            char modPath[MAX_PATH] = { 0 };

            if (!GetModuleBaseNameA(hProcess, hMods[i], modName, MAX_PATH)) {
                continue;
            }

            std::string lowerName = modName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            bool isVulkanModule = (lowerName.find("vulkan") != std::string::npos) ||
                (lowerName.find("nvogl") != std::string::npos) ||
                (lowerName.find("ati") != std::string::npos) ||
                (lowerName.find("ig") == 0 && lowerName.find("icd") != std::string::npos) ||
                (lowerName.find("overlay") != std::string::npos);

            if (!isVulkanModule) {
                continue;
            }

            if (!GetModuleFileNameExA(hProcess, hMods[i], modPath, MAX_PATH)) {
                continue;
            }

            MODULEINFO modInfo = { 0 };
            if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                continue;
            }

            VulkanModuleInfo info;
            info.name = modName;
            info.path = modPath;
            info.baseAddress = (uintptr_t)modInfo.lpBaseOfDll;
            info.size = modInfo.SizeOfImage;
            info.isSystemPath = IsSystemPath(modPath);
            info.isSigned = CheckDigitalSignature(modPath);

            if (!info.isSystemPath || info.name == "vulkan-1.dll") {
                info.hash = GetModuleHash(modPath);
            }
            else {
                info.hash = "system_module";
            }

            info.suspiciousSections.clear();

            if (!info.isSystemPath && lowerName == "vulkan-1.dll") {
                info.suspiciousSections.push_back("NON_SYSTEM_VULKAN");
            }

            newModules.push_back(info);
        }
    }
    catch (const std::exception& e) {
        Logs(VulkanLogLevel::WARNING, std::string("Exception in ScanVulkanModules: ") + e.what());
        return;
    }
    catch (...) {
        Logs(VulkanLogLevel::WARNING, "Exception in ScanVulkanModules");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_vulkanModules = newModules;
        if (m_vulkanModules.size() > MAX_MODULES_STORAGE) {
            m_vulkanModules.resize(MAX_MODULES_STORAGE);
        }
    }

    for (const auto& mod : newModules) {
        if (!mod.isSystemPath && mod.name == "vulkan-1.dll") {
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);
        }
    }
}
void VulkanDetector::InitializeFunctionList() {
    std::vector<VulkanFunction> newFunctions;

    try {
        HMODULE vulkanModule = GetModuleHandleA("vulkan-1.dll");
        if (!vulkanModule) {
            vulkanModule = LoadLibraryA("vulkan-1.dll");
            if (!vulkanModule) {
                Logs(VulkanLogLevel::INFO, "Vulkan not loaded in process");
                return;
            }
        }

        for (const auto& funcName : m_config.criticalFunctions) {
            FARPROC addr = GetProcAddress(vulkanModule, funcName.c_str());
            if (addr) {
                VulkanFunction func;
                func.name = funcName;
                func.address = (uintptr_t)addr;
                func.isCritical = true;
                newFunctions.push_back(func);
            }
        }

        for (const auto& funcName : m_config.importantFunctions) {
            FARPROC addr = GetProcAddress(vulkanModule, funcName.c_str());
            if (addr) {
                VulkanFunction func;
                func.name = funcName;
                func.address = (uintptr_t)addr;
                func.isCritical = false;
                newFunctions.push_back(func);
            }
        }
    }
    catch (const std::exception& e) {
        Logs(VulkanLogLevel::WARNING, std::string("Exception in InitializeFunctionList: ") + e.what());
        return;
    }
    catch (...) {
        Logs(VulkanLogLevel::WARNING, "Exception in InitializeFunctionList");
        return;
    }

    m_monitoredFunctions = newFunctions;

    if (newFunctions.empty()) {
        Logs(VulkanLogLevel::INFO, "Vulkan not loaded in process");
    }

    for (const auto& func : newFunctions) {
        if (func.isCritical) {
            char addrStr[32];
            sprintf_s(addrStr, "0x%p", (void*)func.address);
            Logs(VulkanLogLevel::INFO, "Monitoring " + func.name + " at " + addrStr);
        }
    }
}
bool VulkanDetector::CheckFunctionForHook(const VulkanFunction& func) {
    uint8_t currentBytes[16] = { 0 };
    uintptr_t target = 0;
    std::string hookModulePath;
    std::string hookModule;
    HMODULE vulkanModule = nullptr;
    HMODULE targetModule = nullptr;

    try {
        if (!SafeReadMemory(func.address, currentBytes, sizeof(currentBytes))) {
            return false;
        }

        if (currentBytes[0] == 0xE9 || currentBytes[0] == 0xE8 ||
            (currentBytes[0] == 0xFF && currentBytes[1] == 0x25)) {

            target = CalculateHookTarget(func.address, currentBytes, sizeof(currentBytes));
            if (target == 0) return false;

            hookModule = GetModuleByAddress(target, hookModulePath);
            vulkanModule = GetModuleHandleA("vulkan-1.dll");

            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                (LPCSTR)target, &targetModule);

            if (targetModule && targetModule != vulkanModule) {
                VulkanHookInfo info;
                info.timestamp = GetTickMs();
                info.functionName = func.name;
                info.originalAddress = func.address;
                info.hookAddress = target;
                info.hookModule = hookModule;
                info.hookModulePath = hookModulePath;
                memcpy(info.hookBytes, currentBytes, sizeof(info.hookBytes));
                info.hookType = AnalyzeHookType(currentBytes, sizeof(currentBytes));
                info.isCritical = func.isCritical;

                bool isWhitelisted = IsModuleWhitelisted(hookModule, hookModulePath);
                bool isSystemPath = IsSystemPath(hookModulePath);
                bool isSigned = CheckDigitalSignature(hookModulePath);

                info.confidence = 70;

                if (!isWhitelisted) info.confidence += 15;
                if (!isSystemPath) info.confidence += 10;
                if (!isSigned) info.confidence += 5;
                if (func.isCritical) info.confidence += 5;

                if (info.confidence > 100) info.confidence = 100;

                if (info.confidence >= 70 && !hookModulePath.empty() && hookModulePath != "unknown") {
                    info.hookModuleHash = GetModuleHash(hookModulePath);
                }

                {
                    std::lock_guard<std::mutex> lock(m_dataMutex);
                    m_detectedHooks.push_back(info);
                    if (m_detectedHooks.size() > MAX_HOOKS_STORAGE) {  // ИСПРАВЛЕНО: MAX_HOOKS_TO_STORE
                        m_detectedHooks.erase(m_detectedHooks.begin());  // ИСПРАВЛЕНО: erase вместо pop_front
                    }
                }

                std::stringstream ss;
                ss << "Hook detected on " << info.functionName
                    << " | Type: " << info.hookType
                    << " | Target: " << hookModule
                    << " | Path: " << (hookModulePath.empty() ? "unknown" : hookModulePath)
                    << " | Confidence: " << info.confidence << "%";

                if (!info.hookModuleHash.empty() && info.hookModuleHash != "failed_to_read_file_or_compute_hash") {
                    ss << " | SHA256: " << info.hookModuleHash;
                }

                VulkanLogLevel level = (info.confidence >= m_config.hookConfidenceThreshold)
                    ? VulkanLogLevel::DETECTION
                    : VulkanLogLevel::WARNING;

                if (level == VulkanLogLevel::DETECTION) {
                    g_detectionAggregator.NotifyDangerousPlayer(0ULL);
                }
                else {
                    Logs(level, ss.str());
                }
                return true;
            }
        }

        if (currentBytes[0] == 0xCC) {
            Logs(VulkanLogLevel::WARNING, "Breakpoint detected on " + func.name);
        }
    }
    catch (const std::exception& e) {
        Logs(VulkanLogLevel::WARNING, std::string("Exception in CheckFunctionForHook: ") + e.what());
        return false;
    }
    catch (...) {
        return false;
    }

    return false;
}
void VulkanDetector::CleanupOldLogKeys() {
    uint64_t now = GetTickMs();
    uint64_t cutoff = now - LOG_KEY_MAX_AGE;  // Удаляем записи старше 10 минут

    size_t before = m_lastLogTime.size();

    if (before == 0) return;  // Нечего чистить

    // Удаляем старые записи
    auto it = m_lastLogTime.begin();
    while (it != m_lastLogTime.end()) {
        if (it->second < cutoff) {
            it = m_lastLogTime.erase(it);
        }
        else {
            ++it;
        }
    }
}
void VulkanDetector::DetectionLoop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
    uint64_t lastModuleScan = 0;
    uint64_t lastHookScan = 0;
    uint64_t lastCacheCleanup = 0;  // Переименовал для ясности
    uint64_t lastDataCleanup = 0;

    while (m_isRunning) {
        try {
            uint64_t now = GetTickMs();

            // ===== 1. ОЧИСТКА КЭША ЛОГОВ - КАЖДЫЕ 10 МИНУТ =====
            if (now - lastCacheCleanup >= LOG_CACHE_CLEANUP_INTERVAL) {
                CleanupOldLogKeys();  // Очищаем старые ключи
                lastCacheCleanup = now;

                // Логируем только если реально что-то очистили
                if (m_lastLogTime.size() > 100) {  // Если осталось много записей
                   // Logs(VulkanLogLevel::INFO, "Log cache after cleanup: " + std::to_string(m_lastLogTime.size()) + " keys");
                }
            }

            // ===== 2. ОЧИСТКА ДАННЫХ (хуков и модулей) - ТОЖЕ КАЖДЫЕ 10 МИНУТ =====
            if (now - lastDataCleanup >= LOG_CACHE_CLEANUP_INTERVAL) {
                CleanupOldData();  // Ваш существующий метод
                lastDataCleanup = now;

                // Логируем статистику после очистки
               // Logs(VulkanLogLevel::INFO,"Data cleanup: Hooks=" + std::to_string(m_detectedHooks.size()) + " Modules=" + std::to_string(m_vulkanModules.size()));
            }

            // ===== 3. СКАНИРОВАНИЕ МОДУЛЕЙ (раз в 30 секунд) =====
            if (m_config.enableModuleScan &&
                (now - lastModuleScan >= (uint64_t)m_config.moduleScanIntervalMs)) {
                ScanVulkanModules();
                lastModuleScan = now;
            }

            // ===== 4. ПРОВЕРКА ХУКОВ (раз в 5 секунд) =====
            if (m_config.enableHookDetection &&
                (now - lastHookScan >= (uint64_t)m_config.scanIntervalMs)) {
                for (const auto& func : m_monitoredFunctions) {
                    CheckFunctionForHook(func);
                }
                lastHookScan = now;
            }

            // Короткий сон (не блокируем CPU)
            for (int i = 0; i < 10 && m_isRunning; i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        catch (const std::exception& e) {
           // Logs(VulkanLogLevel::WARNING, std::string("Exception in detection loop: ") + e.what());
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}
std::vector<VulkanHookInfo> VulkanDetector::GetDetectedHooks() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return m_detectedHooks;
}
std::vector<VulkanModuleInfo> VulkanDetector::GetVulkanModules() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return m_vulkanModules;
}
void VulkanDetector::ClearDetectedHooks() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    m_detectedHooks.clear();
}
std::string VulkanDetector::GetStatus() {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    std::stringstream ss;
    ss << "Vulkan Detector Status:";
    ss << "  Running: " << (m_isRunning ? "Yes" : "No") << "";
    ss << "  Initialized: " << (m_initialized ? "Yes" : "No") << "";
    ss << "  Monitored functions: " << m_monitoredFunctions.size() << "";
    ss << "  Detected hooks: " << m_detectedHooks.size() << "";
    ss << "  Vulkan modules: " << m_vulkanModules.size() << "";

    if (!m_detectedHooks.empty()) {
        auto& last = m_detectedHooks.back();
        ss << "  Last hook: " << last.functionName
            << " -> " << last.hookModule
            << " (" << last.confidence << "%)";

        if (!last.hookModuleHash.empty() && last.hookModuleHash != "failed_to_read_file_or_compute_hash") {
            ss << "  Last hash: " << last.hookModuleHash << "";
        }
    }

    return ss.str();
}
std::string VulkanDetector::GetStatistics() {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    std::stringstream ss;
    ss << "Vulkan Detector Statistics:";
    ss << "  Total hooks detected: " << m_detectedHooks.size() << "";

    std::map<std::string, int> funcStats;
    for (const auto& hook : m_detectedHooks) {
        funcStats[hook.functionName]++;
    }

    if (!funcStats.empty()) {
        ss << "  Hooks by function:";
        for (const auto& stat : funcStats) {
            ss << "    " << stat.first << ": " << stat.second << "";
        }
    }

    int suspiciousModules = 0;
    for (const auto& mod : m_vulkanModules) {
        if (!mod.isSystemPath && mod.name == "vulkan-1.dll") {
            suspiciousModules++;
            ss << "  Suspicious vulkan-1.dll: " << mod.path << "";
            if (!mod.hash.empty() && mod.hash != "system_module" && mod.hash != "failed_to_read_file_or_compute_hash") {
                ss << "    SHA256: " << mod.hash;
            }
        }
    }

    return ss.str();
}
void VulkanDetector::CleanupOldData() {
    std::lock_guard<std::mutex> lock(m_dataMutex);

    // Очистка хуков - оставляем только последние MAX_HOOKS_STORAGE
    if (m_detectedHooks.size() > MAX_HOOKS_STORAGE) {
        size_t toRemove = m_detectedHooks.size() - MAX_HOOKS_STORAGE;
        m_detectedHooks.erase(m_detectedHooks.begin(),
            m_detectedHooks.begin() + toRemove);
    }

    // Очистка модулей - оставляем только последние MAX_MODULES_STORAGE
    if (m_vulkanModules.size() > MAX_MODULES_STORAGE) {
        size_t toRemove = m_vulkanModules.size() - MAX_MODULES_STORAGE;
        m_vulkanModules.erase(m_vulkanModules.begin(),
            m_vulkanModules.begin() + toRemove);
    }

    uint64_t now = GetTickMs();
    for (auto it = m_lastLogTime.begin(); it != m_lastLogTime.end(); ) {
        if (now - it->second > 600000) { // Старше 10 минут
            it = m_lastLogTime.erase(it);
        }
        else {
            ++it;
        }
    }
}