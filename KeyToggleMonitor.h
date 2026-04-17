#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <deque>
#include <map>
#include <vector>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cmath>
#include <unordered_set>

class KeyToggleMonitor {
private:
    struct KeyState {
        DWORD vkCode;
        std::string keyName;
        bool wasPressed;
        std::chrono::steady_clock::time_point lastPressTime;
        std::chrono::steady_clock::time_point lastReleaseTime;
        std::chrono::steady_clock::time_point lastDetectionTime;
        std::deque<std::chrono::steady_clock::time_point> pressTimes;
        std::deque<long long> holdDurations;
        std::deque<std::chrono::steady_clock::time_point> holdTimePoints;
        int totalPresses;
        int suspiciousCount;
        float currentSuspicion;
        bool inCooldown;

        KeyState(DWORD code, const std::string& name)
            : vkCode(code)
            , keyName(name)
            , wasPressed(false)
            , lastPressTime()
            , lastReleaseTime()
            , lastDetectionTime()
            , totalPresses(0)
            , suspiciousCount(0)
            , currentSuspicion(0.0f)
            , inCooldown(false)
        {
            lastDetectionTime = std::chrono::steady_clock::time_point();
            lastPressTime = std::chrono::steady_clock::time_point();
            lastReleaseTime = std::chrono::steady_clock::time_point();
        }

        KeyState()
            : vkCode(0)
            , keyName("")
            , wasPressed(false)
            , lastPressTime()
            , lastReleaseTime()
            , lastDetectionTime()
            , totalPresses(0)
            , suspiciousCount(0)
            , currentSuspicion(0.0f)
            , inCooldown(false)
        {
            lastDetectionTime = std::chrono::steady_clock::time_point();
            lastPressTime = std::chrono::steady_clock::time_point();
            lastReleaseTime = std::chrono::steady_clock::time_point();
        }
    };

    struct Config {
        // Мониторируемые клавиши (расширенный список для большего охвата)
        std::vector<DWORD> monitoredKeys = {
            VK_INSERT,  // #1
            VK_HOME,    // #2
            VK_END,     // #3  
            VK_DELETE,  // #4
            VK_F5,      // #5 (часто используется в читах)
            VK_F6,      // #6
            VK_F7,      // #7
            VK_F8,      // #8
            VK_F9,      // #9
            VK_F10,     // #10
            VK_F11,     // #11
            VK_F12,     // #12
            VK_NUMPAD0, // #13
            VK_NUMPAD1, // #14
            VK_NUMPAD2, // #15
            VK_NUMPAD3, // #16
            VK_NUMPAD4, // #17
            VK_NUMPAD5, // #18
            VK_NUMPAD6, // #19
            VK_NUMPAD7, // #20
            VK_NUMPAD8, // #21
            VK_NUMPAD9, // #22
            VK_PRIOR,   // #23 PGUP
            VK_NEXT,    // #24 PGDN
        };

        // Группы риска (расширяем высокий риск)
        std::unordered_set<DWORD> highRiskKeys = {
            VK_INSERT, VK_HOME, VK_END, VK_DELETE,
            VK_F5, VK_F6, VK_F7, VK_F8,
            VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2
        };
        std::unordered_set<DWORD> mediumRiskKeys = {
            VK_F9, VK_F10, VK_F11, VK_F12,
            VK_NUMPAD3, VK_NUMPAD4, VK_NUMPAD5,
            VK_PRIOR, VK_NEXT
        };
        std::unordered_set<DWORD> lowRiskKeys = {
            VK_NUMPAD6, VK_NUMPAD7, VK_NUMPAD8, VK_NUMPAD9
        };

        // Основные настройки
        int pollInterval = 20; // Уменьшаем интервал для более частой проверки

        // ПОНИЖАЕМ пороги срабатывания для большей чувствительности
        float highRiskThreshold = 0.50f;    // Было 0.70f
        float mediumRiskThreshold = 0.60f;  // Было 0.80f
        float lowRiskThreshold = 0.70f;     // Было 0.90f

        // Уменьшаем временные окна для более быстрой реакции
        int reconWindowSec = 30;    // Было 60
        int combatWindowSec = 15;   // Было 30
        int spamWindowSec = 5;      // Было 10
        int clusterWindowSec = 90;  // Было 180

        // Уменьшаем лимиты для более частых срабатываний
        int maxReconToggles = 2;    // Было 3
        int maxCombatToggles = 3;   // Было 4
        int maxSpamPresses = 2;     // Было 3
        int maxPressesPerCluster = 3; // Было 4
        int minPressesForPattern = 2; // Было 3

        // Время удержания (расширяем диапазоны)
        int minReconHoldTime = 300;      // Было 500
        int maxReconHoldTime = 60000;    // Было 30000 (увеличиваем для большего охвата)
        int idealReconHoldTime = 5000;   // Было 10000

        int minHoldTime = 20;            // Было 30
        int quickTapThreshold = 80;      // Было 100
        int normalTapThreshold = 250;    // Было 300
        int longPressThreshold = 800;    // Было 1000
        int maxHoldTime = 60000;         // Было 30000

        // УВЕЛИЧИВАЕМ веса для большей чувствительности
        float reconPatternWeight = 0.9f;   // Было 0.7f
        float combatPatternWeight = 0.6f;  // Было 0.4f
        float spamPatternWeight = 0.5f;    // Было 0.3f
        float regularityWeight = 0.2f;     // Было 0.1f

        // Уменьшаем защиту от ложных срабатываний
        int cooldownAfterDetectionSec = 180;  // Было 300
        float suspicionDecayPerMin = 0.2f;    // Было 0.3f (медленнее затухание)
        int minDetectionIntervalSec = 60;     // Было 120

        // Логирование (включаем подробное)
        bool logAllPresses = true;           // Было false
        bool logDetectionDetails = true;
        int debugLogInterval = 25;           // Было 50 (чаще логируем)
        bool enableScreenshotOnDetection = true;

        // Умная детекция (делаем более строгой)
        float patternVarianceThreshold = 0.15f;  // Было 0.25f (меньше отклонение)
        bool checkForHumanPattern = false;      // Было true (отключаем проверку на человечность)
        int minHumanIntervalSec = 1;            // Было 2
        int maxHumanIntervalSec = 30;           // Было 60
        bool allowSinglePress = false;          // Было true (теперь и одиночные нажатия подозрительны)
        int maxSinglePressesPerHour = 1;        // Было 2
        bool detectClusteredPresses = true;

        // Дополнительные настройки (увеличиваем историю)
        int maxPressHistory = 150;      // Было 100
        int maxHoldHistory = 75;        // Было 50
        int cleanupIntervalMinutes = 10; // Было 5
    };

    // Данные
    Config config;
    std::map<DWORD, KeyState> keyStates;
    mutable std::mutex dataMutex;
    std::atomic<bool> isRunning;
    std::thread pollingThread;

    // Статистика
    struct GlobalStats {
        int totalDetections;
        int suspiciousDetections;
        int totalKeyEvents;
        int patternDetections;
        std::chrono::steady_clock::time_point startTime;
        std::map<std::string, int> patternCounts;
        std::map<DWORD, int> keyDetectionCounts;

        GlobalStats()
            : totalDetections(0)
            , suspiciousDetections(0)
            , totalKeyEvents(0)
            , patternDetections(0)
            , startTime(std::chrono::steady_clock::now())
        {
        }
    } globalStats;

    // Приватные методы
    void PollingThread();
    void PollKeys();
    void ProcessKeyPress(DWORD vkCode, KeyState& state);
    void ProcessKeyRelease(DWORD vkCode, KeyState& state, long long holdTime);
    void AnalyzeKeyPatterns(KeyState& state);

    // Методы расчета
    float CalculateReconSuspicion(KeyState& state);
    float CalculateCombatSuspicion(KeyState& state);
    float CalculateSpamSuspicion(KeyState& state);
    float CalculateRegularitySuspicion(KeyState& state);
    float CalculateHoldTimeSuspicion(long long holdTime) const;
    float CalculateHumanPatternSuspicion(KeyState& state);

    // Вспомогательные методы
    float GetKeyRiskMultiplier(DWORD vkCode) const;
    float GetKeyThreshold(DWORD vkCode) const;
    std::string DeterminePatternType(float recon, float combat, float spam, float regularity) const;
    void UpdateSuspicionDecay(KeyState& state);
    bool CheckAndUpdateCooldown(KeyState& state);
    void ApplyCooldown(KeyState& state);
    bool CheckHumanPattern(const KeyState& state) const;
    bool CheckClusteredPresses(const KeyState& state) const;

    // Методы логирования
    void LogDetection(DWORD vkCode, const std::string& pattern, float suspicion, const KeyState& state);
    void DebugLogPress(DWORD vkCode, const std::string& action, long long holdTime = 0) const;
    void UpdateGlobalStats(const std::string& pattern, DWORD vkCode);
    void CleanupOldData();

    // Служебные методы
    void TrimPressHistory(KeyState& state, const std::chrono::steady_clock::time_point& cutoff);
    void TrimHoldHistory(KeyState& state, const std::chrono::steady_clock::time_point& cutoff);

    // Утилиты
    static std::string VirtualKeyToString(DWORD vkCode);
    static bool IsGameWindowActive();

public:
    KeyToggleMonitor();
    ~KeyToggleMonitor();

    // Основные методы
    bool Start();
    void Stop();
    void Pause();
    void Resume();

    // Статистика
    int GetTotalDetections() const;
    int GetSuspiciousDetections() const;
    int GetTotalKeyEvents() const;
    int GetKeyDetectionCount(DWORD vkCode) const;
    std::string GetStatsString() const;
    std::string GetDetailedStats() const;
    std::map<DWORD, std::string> GetKeyStates() const;
    bool IsRunning() const;

    // Настройки
    void SetPollInterval(int ms);
    void AddMonitoredKey(DWORD vkCode);
    void RemoveMonitoredKey(DWORD vkCode);
    void SetLogAllPresses(bool enabled);
    void SetDetectionThreshold(float threshold);
    void SetCooldownTime(int seconds);
    void ClearAllData();
    void ResetStats();
    void SetPatternWeights(float recon, float combat, float spam, float regularity);
    void SetTimeWindows(int reconSec, int combatSec, int spamSec);
    void SetRiskLevels(const std::vector<DWORD>& highRisk, const std::vector<DWORD>& mediumRisk, const std::vector<DWORD>& lowRisk);
    void SetHistoryLimits(int maxPressHistory, int maxHoldHistory);
};
extern KeyToggleMonitor* g_keyMonitor;
// Глобальные функции
void StartKeyToggleMonitoring();
void StopKeyToggleMonitoring();
bool IsKeyMonitoringActive();
std::string GetKeyMonitorStats();
void AddKeyToMonitor(DWORD vkCode);
void RemoveKeyFromMonitor(DWORD vkCode);
void SetKeyMonitorLogging(bool enabled);