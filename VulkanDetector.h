// VulkanDetector.h
#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <map>
#include <deque>
#include <sstream>
#include <iomanip>
#include <intrin.h>
#include <psapi.h>
#include <vulkan/vulkan.h>
#include <vulkan/vulkan_win32.h>

#pragma comment(lib, "vulkan-1.lib")
#pragma comment(lib, "psapi.lib")

// Типы логирования
enum class VulkanLogLevel {
    INFO,      // [LOGEN] - общая информация
    WARNING,   // [LOGEN] - предупреждения
    DETECTION  // [VEH] - детекция чита
};

// Информация о найденном хуке
struct VulkanHookInfo {
    uint64_t timestamp;                 // Время обнаружения
    std::string functionName;           // Название функции
    uintptr_t originalAddress;          // Оригинальный адрес
    uintptr_t hookAddress;              // Адрес назначения хука
    std::string hookModule;             // Имя модуля с хуком
    std::string hookModulePath;         // Полный путь к модулю
    std::string hookModuleHash;         // SHA256 модуля
    uint8_t hookBytes[16];               // Первые байты функции
    std::string hookType;                // Тип хука
    int confidence;                      // 0-100
    bool isCritical;                     // Критическая детекция
};

// Информация о модуле Vulkan
struct VulkanModuleInfo {
    std::string name;
    std::string path;
    std::string hash;
    bool isSystemPath;
    bool isSigned;
    uintptr_t baseAddress;
    size_t size;
    std::vector<std::string> suspiciousSections;
};

// Конфигурация детектора
struct VulkanDetectorConfig {
    bool enableHookDetection = true;          // Поиск хуков
    bool enableModuleScan = true;             // Сканирование модулей
    bool enableSignatureCheck = true;         // Проверка подписей
    bool enableScreenshotOnDetection = true;  // Скриншот при детекции

    // Пороги
    int hookConfidenceThreshold = 80;          // Минимальный confidence для [VEH]
    int scanIntervalMs = 5000;                  // Интервал сканирования (5 сек)
    int moduleScanIntervalMs = 30000;           // Интервал сканирования модулей (30 сек)

    // Критические функции для мониторинга
    std::vector<std::string> criticalFunctions = {
        "vkQueuePresentKHR",
        "vkPresentInfoKHR",
        "vkCreateSwapchainKHR"
    };

    // Важные функции (логируются как INFO)
    std::vector<std::string> importantFunctions = {
        "vkAcquireNextImageKHR",
        "vkQueueSubmit",
        "vkCmdDraw",
        "vkCmdDrawIndexed",
        "vkCreateGraphicsPipelines",
        "vkCreateShaderModule"
    };

    // Белый список модулей
    std::vector<std::string> whitelistedModules = {
        "vulkan-1.dll",
        "dxgi.dll",
        "d3d11.dll",
        "nvoglv64.dll",
        "nvoglv32.dll",
        "atio6axx.dll",
        "atig6txx.dll",
        "ig4icd64.dll",
        "ig4icd32.dll",
        "steamoverlayvulkan64.dll",
        "gameoverlayvulkan64.dll",
        "discord_overlay.dll",
        "obs-vulkan64.dll"
    };

    // Белый список путей
    std::vector<std::string> whitelistedPaths = {
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\"
    };

    // Подозрительные имена секций
    std::vector<std::string> suspiciousSectionNames = {
        ".gxfg", ".retplne", "_RDATA", ".bind", ".wvm"
    };
};

class VulkanDetector {
private:

    void CleanupOldLogKeys();  // НОВЫЙ МЕТОД
    static const uint64_t LOG_CACHE_CLEANUP_INTERVAL = 300000; 
    static const uint64_t LOG_KEY_MAX_AGE = 300000;  
    uint64_t m_lastForceCleanup = 0;
    // Состояние
    std::atomic<bool> m_isRunning{ false };
    std::atomic<bool> m_initialized{ false };
    std::thread m_detectionThread;
    std::mutex m_dataMutex;

    // Данные
    std::vector<VulkanHookInfo> m_detectedHooks;
    std::vector<VulkanModuleInfo> m_vulkanModules;
    VulkanDetectorConfig m_config;

    // Кэш для rate limiting
    std::map<std::string, uint64_t> m_lastLogTime;

    // Vulkan функции
    struct VulkanFunction {
        std::string name;
        uintptr_t address;
        bool isCritical;
    };
    std::vector<VulkanFunction> m_monitoredFunctions;

    // Приватные методы
    uint64_t GetTickMs();
    bool ShouldLog(const std::string& key, uint64_t cooldownMs);
    void Logs(VulkanLogLevel level, const std::string& message);
    std::string GetModuleHash(const std::string& path);
    bool IsModuleWhitelisted(const std::string& name, const std::string& path);
    bool IsSystemPath(const std::string& path);
    bool CheckDigitalSignature(const std::string& path);
    bool SafeReadMemory(uintptr_t address, void* buffer, size_t size);
    std::string GetModuleByAddress(uintptr_t address, std::string& fullPath);
    std::string AnalyzeHookType(uint8_t* bytes, size_t size);
    uintptr_t CalculateHookTarget(uintptr_t functionAddr, uint8_t* bytes, size_t size);
    bool CheckFunctionForHook(const VulkanFunction& func);
    void ScanVulkanModules();
    void InitializeFunctionList();
    void DetectionLoop();

public:
    VulkanDetector();
    ~VulkanDetector();
    static const size_t MAX_HOOKS_STORAGE = 100;      // Максимум 100 хуков
    static const size_t MAX_MODULES_STORAGE = 20;     // Максимум 20 модулей
    void CleanupOldData();
    // Инициализация и управление
    bool Initialize();
    bool Start();
    void Stop();
    bool IsRunning() const { return m_isRunning; }

    // Конфигурация
    void SetConfig(const VulkanDetectorConfig& config);
    VulkanDetectorConfig& GetConfig() { return m_config; }

    // Получение данных
    std::vector<VulkanHookInfo> GetDetectedHooks();
    std::vector<VulkanModuleInfo> GetVulkanModules();
    void ClearDetectedHooks();

    // Статус
    std::string GetStatus();
    std::string GetStatistics();
};

// Глобальный указатель (опционально)
extern std::unique_ptr<VulkanDetector> g_vulkanDetector;