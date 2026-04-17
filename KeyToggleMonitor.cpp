#include "KeyToggleMonitor.h"
#include "LogUtils.h"
#include "dllmain.h"
#include <cmath>
#include <psapi.h>
#include <algorithm>
#include <numeric>
#pragma comment(lib, "psapi.lib")
KeyToggleMonitor* g_keyMonitor = nullptr;
static std::chrono::steady_clock::time_point GetMinTimePoint() {
    return std::chrono::steady_clock::time_point();
}
KeyToggleMonitor::KeyToggleMonitor()
    : isRunning(false)
{
    globalStats.startTime = std::chrono::steady_clock::now();

    // Инициализация состояний для всех отслеживаемых клавиш
    for (DWORD key : config.monitoredKeys) {
        keyStates[key] = KeyState(key, VirtualKeyToString(key));
    }

    if (g_keyMonitor == nullptr) {
        g_keyMonitor = this;
    }
}
KeyToggleMonitor::~KeyToggleMonitor() {
    Stop();

    if (g_keyMonitor == this) {
        g_keyMonitor = nullptr;
    }
}
bool KeyToggleMonitor::Start() {
    if (isRunning) {
        return true;
    }

    Log("[LOGEN] Starting KeyToggleMonitor (advanced pattern detection)...");

    // Сбрасываем статистику
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        globalStats.totalDetections = 0;
        globalStats.suspiciousDetections = 0;
        globalStats.totalKeyEvents = 0;
        globalStats.patternDetections = 0;
        globalStats.patternCounts.clear();
        globalStats.keyDetectionCounts.clear();
        globalStats.startTime = std::chrono::steady_clock::now();

        for (auto& pair : keyStates) {
            pair.second.wasPressed = false;
            pair.second.totalPresses = 0;
            pair.second.suspiciousCount = 0;
            pair.second.currentSuspicion = 0.0f;
            pair.second.inCooldown = false;
            pair.second.pressTimes.clear();
            pair.second.holdDurations.clear();
            pair.second.holdTimePoints.clear();
            pair.second.lastDetectionTime = GetMinTimePoint();
            pair.second.lastPressTime = GetMinTimePoint();
            pair.second.lastReleaseTime = GetMinTimePoint();
        }
    }

    isRunning = true;
    pollingThread = std::thread(&KeyToggleMonitor::PollingThread, this);

    Log("[LOGEN] KeyToggleMonitor started. Monitoring " + std::to_string(keyStates.size()) + " cheat hotkeys");
    Log("[LOGEN] High risk keys: " + std::to_string(config.highRiskKeys.size()));
    Log("[LOGEN] Medium risk keys: " + std::to_string(config.mediumRiskKeys.size()));
    Log("[LOGEN] Low risk keys: " + std::to_string(config.lowRiskKeys.size()));

    return true;
}
void KeyToggleMonitor::Stop() {
    if (!isRunning) return;

    Log("[LOGEN] Stopping KeyToggleMonitor...");

    isRunning = false;

    if (pollingThread.joinable()) {
        pollingThread.join();
    }

    // Логируем итоговую статистику
    Log("[LOGEN] KeyToggleMonitor stopped. Final stats:");
    Log("[LOGEN] " + GetDetailedStats());
}
void KeyToggleMonitor::Pause() {
    if (!isRunning) return;
    isRunning = false;
    Log("[LOGEN] KeyToggleMonitor paused");
}
void KeyToggleMonitor::Resume() {
    if (isRunning) return;
    isRunning = true;
    Log("[LOGEN] KeyToggleMonitor resumed");
}
void KeyToggleMonitor::PollingThread() {
    Log("[LOGEN] Advanced pattern detection thread started");

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    auto lastStatsLog = std::chrono::steady_clock::now();
    auto lastCleanup = std::chrono::steady_clock::now();

    while (isRunning) {
        try {
            // Основной цикл проверки
            PollKeys();

            // Логируем статистику каждые 60 секунд
            auto now = std::chrono::steady_clock::now();
            auto secondsSinceLastLog = std::chrono::duration_cast<std::chrono::seconds>(now - lastStatsLog).count();

            if (secondsSinceLastLog >= 60) {
                if (globalStats.totalKeyEvents > 0 || globalStats.totalDetections > 0) {
                    std::string stats = GetStatsString();
                    if (!stats.empty()) {
                        Log("[LOGEN] KeyMonitor periodic stats: " + stats);
                    }
                }
                lastStatsLog = now;
            }

            // Очистка старых данных каждые 30 секунд
            auto secondsSinceLastCleanup = std::chrono::duration_cast<std::chrono::seconds>(now - lastCleanup).count();
            if (secondsSinceLastCleanup >= 30) {
                CleanupOldData();
                lastCleanup = now;
            }

            // Интервал опроса
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config.pollInterval));

        }
        catch (const std::exception& e) {
            Log("[LOGEN] KeyMonitor exception: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        catch (...) {
            Log("[LOGEN] KeyMonitor unknown exception");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }

    Log("[LOGEN] Pattern detection thread ended");
}
void KeyToggleMonitor::PollKeys() {
    std::lock_guard<std::mutex> lock(dataMutex);
    auto now = std::chrono::steady_clock::now();

    // Обновляем затухание подозрительности для всех клавиш
    for (auto& pair : keyStates) {
        UpdateSuspicionDecay(pair.second);
    }

    for (auto& pair : keyStates) {
        DWORD vkCode = pair.first;
        KeyState& state = pair.second;

        // Проверяем кд
        if (CheckAndUpdateCooldown(state)) {
            continue;
        }

        SHORT keyState = GetAsyncKeyState(vkCode);
        bool isPressed = (keyState & 0x8000) != 0;

        if (isPressed && !state.wasPressed) {
            // Новое нажатие
            state.lastPressTime = now;
            state.wasPressed = true;
            globalStats.totalKeyEvents++;

            ProcessKeyPress(vkCode, state);

            if (config.logAllPresses) {
               // DebugLogPress(vkCode, "PRESS");
            }
        }
        else if (!isPressed && state.wasPressed) {
            // Клавиша отпущена
            state.wasPressed = false;
            state.lastReleaseTime = now;

            // Рассчитываем время удержания
            auto holdDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - state.lastPressTime).count();

            ProcessKeyRelease(vkCode, state, holdDuration);
        }
    }
}
void KeyToggleMonitor::ProcessKeyPress(DWORD vkCode, KeyState& state) {
    auto now = std::chrono::steady_clock::now();

    // Сохраняем время нажатия
    state.pressTimes.push_back(now);
    state.totalPresses++;

    // Ограничиваем размер истории
    if (state.pressTimes.size() > config.maxPressHistory) {
        state.pressTimes.pop_front();
    }

    // Дебаг логирование
    static int debugCounter = 0;
    if (config.logAllPresses && (++debugCounter % config.debugLogInterval == 0)) {
       // DebugLogPress(vkCode, "DEBUG_PRESS", state.totalPresses);
    }
}
void KeyToggleMonitor::ProcessKeyRelease(DWORD vkCode, KeyState& state, long long holdTime) {
    auto now = std::chrono::steady_clock::now();

    // Сохраняем время удержания с синхронизацией по времени
    if (holdTime >= config.minHoldTime && holdTime <= config.maxHoldTime) {
        state.holdDurations.push_back(holdTime);
        state.holdTimePoints.push_back(now);

        // Ограничиваем размер истории
        if (state.holdDurations.size() > config.maxHoldHistory) {
            state.holdDurations.pop_front();
            state.holdTimePoints.pop_front();
        }

        // Анализируем время удержания
        float holdSuspicion = CalculateHoldTimeSuspicion(holdTime);

        // Паттерн "Разведка" - долгое нажатие
        if (holdTime >= config.minReconHoldTime && holdTime <= config.maxReconHoldTime) {
            float diff = static_cast<float>(std::abs(holdTime - config.idealReconHoldTime));
            float maxDiff = static_cast<float>(config.maxReconHoldTime - config.minReconHoldTime);
            float reconScore = std::max(0.0f, 1.0f - (diff / maxDiff));
            state.currentSuspicion += reconScore * 0.3f;

            if (config.logAllPresses) {
               // DebugLogPress(vkCode, "RECON_HOLD", holdTime);
            }
        }

        // Быстрое нажатие - подозрительно
        if (holdSuspicion > 0.6f) {
            state.currentSuspicion += 0.15f;
        }
    }

    // Анализируем паттерны если достаточно нажатий
    if (state.pressTimes.size() >= config.minPressesForPattern) {
        AnalyzeKeyPatterns(state);
    }

    if (config.logAllPresses) {
       // DebugLogPress(vkCode, "RELEASE", holdTime);
    }
}
void KeyToggleMonitor::AnalyzeKeyPatterns(KeyState& state) {
    if (state.pressTimes.size() < config.minPressesForPattern) {
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // 1. Паттерн "Разведка"
    float reconSuspicion = CalculateReconSuspicion(state);

    // 2. Паттерн "Бой"
    float combatSuspicion = CalculateCombatSuspicion(state);

    // 3. Паттерн "Спам"
    float spamSuspicion = CalculateSpamSuspicion(state);

    // 4. Проверка на регулярность
    float regularitySuspicion = CalculateRegularitySuspicion(state);

    // 5. Умная проверка
    float humanPatternSuspicion = CalculateHumanPatternSuspicion(state);

    // 6. Множитель риска
    float riskMultiplier = GetKeyRiskMultiplier(state.vkCode);

    // 7. Общая подозрительность
    float patternSuspicion = (
        std::max(0.0f, reconSuspicion) * config.reconPatternWeight +
        std::max(0.0f, combatSuspicion) * config.combatPatternWeight +
        std::max(0.0f, spamSuspicion) * config.spamPatternWeight +
        std::max(0.0f, regularitySuspicion) * config.regularityWeight
        ) * riskMultiplier;

    // Добавляем человеческий фактор
    patternSuspicion += humanPatternSuspicion;

    // Добавляем текущую накопленную
    patternSuspicion += state.currentSuspicion;

    // Ограничиваем диапазон
    patternSuspicion = std::min(std::max(patternSuspicion, 0.0f), 1.0f);

    // Порог срабатывания
    float threshold = GetKeyThreshold(state.vkCode);

    if (patternSuspicion >= threshold) {
        // Определяем основной паттерн
        std::string patternType = DeterminePatternType(
            std::max(0.0f, reconSuspicion),
            std::max(0.0f, combatSuspicion),
            std::max(0.0f, spamSuspicion),
            std::max(0.0f, regularitySuspicion)
        );

        // Если сработала кластеризация
        if (config.detectClusteredPresses && CheckClusteredPresses(state)) {
            patternType = "CLUSTER_" + patternType;
        }

        // Регистрируем детекцию
        state.suspiciousCount++;
        state.lastDetectionTime = now;
        globalStats.totalDetections++;
        globalStats.suspiciousDetections++;
        globalStats.patternDetections++;

        UpdateGlobalStats(patternType, state.vkCode);
        LogDetection(state.vkCode, patternType, patternSuspicion, state);

        ApplyCooldown(state);
        state.currentSuspicion = 0.0f;
    }
}
float KeyToggleMonitor::CalculateReconSuspicion(KeyState& state) {
    if (state.holdDurations.size() < 2) return 0.0f;

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(config.reconWindowSec);

    int reconPresses = 0;
    for (size_t i = 0; i < state.holdDurations.size(); i++) {
        if (i < state.holdTimePoints.size() && state.holdTimePoints[i] > cutoff) {
            long long holdTime = state.holdDurations[i];
            if (holdTime >= config.minReconHoldTime && holdTime <= config.maxReconHoldTime) {
                reconPresses++;
            }
        }
    }

    if (reconPresses > config.maxReconToggles) {
        float excess = static_cast<float>(reconPresses - config.maxReconToggles) / config.maxReconToggles;
        return std::min(0.3f + excess * 0.7f, 1.0f);
    }

    return 0.0f;
}
float KeyToggleMonitor::CalculateCombatSuspicion(KeyState& state) {
    if (state.pressTimes.size() < 3) return 0.0f;

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(config.combatWindowSec);

    // Считаем только нажатия в окне
    std::vector<std::chrono::steady_clock::time_point> recentPresses;
    for (const auto& pressTime : state.pressTimes) {
        if (pressTime > cutoff) {
            recentPresses.push_back(pressTime);
        }
    }

    int recentPressCount = static_cast<int>(recentPresses.size());
    if (recentPressCount > config.maxCombatToggles) {
        float excess = static_cast<float>(recentPressCount - config.maxCombatToggles) / config.maxCombatToggles;
        return std::min(0.4f + excess * 0.6f, 1.0f);
    }

    // Анализируем интервалы
    if (recentPresses.size() >= 3) {
        std::vector<long long> intervals;
        for (size_t i = 1; i < recentPresses.size(); i++) {
            auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
                recentPresses[i] - recentPresses[i - 1]).count();
            if (interval > 0) {
                intervals.push_back(interval);
            }
        }

        if (intervals.size() >= 2) {
            int combatIntervals = 0;
            for (long long interval : intervals) {
                if (interval >= 1000 && interval <= 5000) {
                    combatIntervals++;
                }
            }

            float combatRatio = static_cast<float>(combatIntervals) / intervals.size();
            if (combatRatio > 0.5f) {
                return 0.5f + (combatRatio - 0.5f) * 1.0f;
            }
        }
    }

    return 0.0f;
}
float KeyToggleMonitor::CalculateSpamSuspicion(KeyState& state) {
    if (state.pressTimes.size() < 2) return 0.0f;

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(config.spamWindowSec);

    int spamPresses = 0;
    for (const auto& pressTime : state.pressTimes) {
        if (pressTime > cutoff) {
            spamPresses++;
        }
    }

    if (spamPresses > config.maxSpamPresses) {
        float excess = static_cast<float>(spamPresses - config.maxSpamPresses) / config.maxSpamPresses;
        return std::min(0.5f + excess * 0.5f, 1.0f);
    }

    return 0.0f;
}
float KeyToggleMonitor::CalculateRegularitySuspicion(KeyState& state) {
    if (state.holdDurations.size() < 4) return 0.0f;

    long long sum = 0;
    for (long long duration : state.holdDurations) {
        sum += duration;
    }

    if (sum == 0) return 0.0f;

    float mean = static_cast<float>(sum) / state.holdDurations.size();

    float variance = 0.0f;
    for (long long duration : state.holdDurations) {
        float diff = static_cast<float>(duration) - mean;
        variance += diff * diff;
    }
    variance /= state.holdDurations.size();

    float stdDev = std::sqrt(variance);
    float cv = (mean > 0) ? (stdDev / mean) : 1.0f;

    if (cv < config.patternVarianceThreshold) {
        return 0.7f + (config.patternVarianceThreshold - cv) * 1.5f;
    }

    return 0.0f;
}
float KeyToggleMonitor::CalculateHoldTimeSuspicion(long long holdTime) const {
    if (holdTime < config.minHoldTime) {
        return 0.0f;
    }
    else if (holdTime < config.quickTapThreshold) {
        float ratio = static_cast<float>(holdTime - config.minHoldTime) /
            (config.quickTapThreshold - config.minHoldTime);
        return 0.5f + (1.0f - ratio) * 0.5f;
    }
    else if (holdTime < config.normalTapThreshold) {
        float ratio = static_cast<float>(holdTime - config.quickTapThreshold) /
            (config.normalTapThreshold - config.quickTapThreshold);
        return 0.3f + (1.0f - ratio) * 0.2f;
    }
    else if (holdTime < config.longPressThreshold) {
        float ratio = static_cast<float>(holdTime - config.normalTapThreshold) /
            (config.longPressThreshold - config.normalTapThreshold);
        return ratio * 0.3f;
    }

    return 0.0f;
}
float KeyToggleMonitor::CalculateHumanPatternSuspicion(KeyState& state) {
    if (!config.checkForHumanPattern) return 0.0f;

    float suspicion = 0.0f;

    // 1. Если паттерн "человеческий" - уменьшаем подозрительность
    if (CheckHumanPattern(state)) {
        suspicion -= 0.3f;
    }

    // 2. Если нажатия сгруппированы - увеличиваем подозрительность
    if (config.detectClusteredPresses && CheckClusteredPresses(state)) {
        suspicion += 0.4f;
    }

    // 3. Анализируем время удержания
    if (!state.holdDurations.empty()) {
        long long totalHold = 0;
        int count = 0;

        for (long long hold : state.holdDurations) {
            if (hold >= config.longPressThreshold) {
                totalHold += hold;
                count++;
            }
        }

        if (count > 0) {
            float avgHold = static_cast<float>(totalHold) / count;
            if (avgHold >= 5000 && avgHold <= 15000) {
                suspicion += 0.2f;
            }
        }
    }

    return suspicion;
}
float KeyToggleMonitor::GetKeyRiskMultiplier(DWORD vkCode) const {
    if (config.highRiskKeys.find(vkCode) != config.highRiskKeys.end()) return 1.2f;
    if (config.mediumRiskKeys.find(vkCode) != config.mediumRiskKeys.end()) return 1.0f;
    if (config.lowRiskKeys.find(vkCode) != config.lowRiskKeys.end()) return 0.8f;
    return 1.0f;
}
float KeyToggleMonitor::GetKeyThreshold(DWORD vkCode) const {
    if (config.highRiskKeys.find(vkCode) != config.highRiskKeys.end()) return config.highRiskThreshold;
    if (config.mediumRiskKeys.find(vkCode) != config.mediumRiskKeys.end()) return config.mediumRiskThreshold;
    return config.lowRiskThreshold;
}
std::string KeyToggleMonitor::DeterminePatternType(float recon, float combat, float spam, float regularity) const {
    if (recon > 0.5f && recon >= combat && recon >= spam && recon >= regularity) {
        return "RECON_TOGGLE";
    }
    else if (combat > 0.5f && combat >= recon && combat >= spam && combat >= regularity) {
        return "COMBAT_TOGGLE";
    }
    else if (spam > 0.6f) {
        return "KEY_SPAM";
    }
    else if (regularity > 0.7f) {
        return "BOT_PATTERN";
    }
    else if (recon > 0.3f || combat > 0.3f || spam > 0.4f || regularity > 0.5f) {
        return "MIXED_PATTERN";
    }
    else {
        return "UNKNOWN_PATTERN";
    }
}
void KeyToggleMonitor::UpdateSuspicionDecay(KeyState& state) {
    auto now = std::chrono::steady_clock::now();
    auto timeSinceLastActivity = std::chrono::duration_cast<std::chrono::minutes>(
        now - state.lastReleaseTime).count();

    if (timeSinceLastActivity > 0) {
        state.currentSuspicion -= config.suspicionDecayPerMin * timeSinceLastActivity;
        if (state.currentSuspicion < 0) {
            state.currentSuspicion = 0.0f;
        }
    }
}
bool KeyToggleMonitor::CheckAndUpdateCooldown(KeyState& state) {
    if (!state.inCooldown) return false;

    auto now = std::chrono::steady_clock::now();
    auto timeSinceDetection = std::chrono::duration_cast<std::chrono::seconds>(
        now - state.lastDetectionTime).count();

    if (timeSinceDetection >= config.cooldownAfterDetectionSec) {
        state.inCooldown = false;
        return false;
    }

    return true;
}
void KeyToggleMonitor::ApplyCooldown(KeyState& state) {
    state.inCooldown = true;
}
bool KeyToggleMonitor::CheckHumanPattern(const KeyState& state) const {
    if (state.pressTimes.size() < 2) return false;

    std::vector<long long> intervals;
    auto prevTime = state.pressTimes.front();

    for (size_t i = 1; i < state.pressTimes.size(); i++) {
        auto interval = std::chrono::duration_cast<std::chrono::seconds>(
            state.pressTimes[i] - prevTime).count();

        if (interval > 0) {
            intervals.push_back(interval);
        }
        prevTime = state.pressTimes[i];
    }

    if (intervals.empty()) return false;

    int humanIntervals = 0;
    for (long long interval : intervals) {
        if (interval >= config.minHumanIntervalSec && interval <= config.maxHumanIntervalSec) {
            humanIntervals++;
        }
    }

    float humanRatio = static_cast<float>(humanIntervals) / intervals.size();
    return humanRatio > 0.5f;
}
bool KeyToggleMonitor::CheckClusteredPresses(const KeyState& state) const {
    if (state.pressTimes.size() < config.maxPressesPerCluster) return false;

    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(config.clusterWindowSec);

    int clusterPresses = 0;
    for (const auto& pressTime : state.pressTimes) {
        if (pressTime > cutoff) {
            clusterPresses++;
        }
    }

    return clusterPresses >= config.maxPressesPerCluster;
}

// Логирование детекции
void KeyToggleMonitor::LogDetection(DWORD vkCode, const std::string& pattern, float suspicion, const KeyState& state) {
    std::stringstream ss;

    ss << "[VEH] CHEAT_PATTERN_DETECTED | Pattern: " << pattern
        << " | Key: " << state.keyName
        << " (" << std::hex << "0x" << vkCode << std::dec << ")"
        << " | Confidence: " << std::fixed << std::setprecision(0) << (suspicion * 100) << "%"
        << " | Total presses: " << state.totalPresses
        << " | Recent presses: " << state.pressTimes.size()
        << " | Detections: " << state.suspiciousCount;
    /*
    if (!state.holdDurations.empty()) {
        long long avgHold = 0;
        for (long long hold : state.holdDurations) avgHold += hold;
        avgHold /= state.holdDurations.size();
        ss << " | Avg hold: " << avgHold << "ms";

        ss << " | Last holds: ";
        int count = 0;
        for (auto it = state.holdDurations.rbegin(); it != state.holdDurations.rend() && count < 3; ++it) {
            if (count > 0) ss << " ";
            ss << *it << "ms";
            count++;
        }
    }
    */
    std::string logMsg = ss.str();

    Log(logMsg);
    StartSightImgDetection("[VEH] CHEAT_PATTERN_DETECTED | Pattern: " + pattern + " | Key: " + state.keyName);
    /*
    if (config.enableScreenshotOnDetection && (suspicion >= 0.8f || pattern == "RECON_TOGGLE" || pattern == "BOT_PATTERN")) {
        StartSightImg(logMsg);
    }
    */
}

void KeyToggleMonitor::UpdateGlobalStats(const std::string& pattern, DWORD vkCode) {
    globalStats.patternCounts[pattern]++;
    globalStats.keyDetectionCounts[vkCode]++;
}
void KeyToggleMonitor::CleanupOldData() {
    std::lock_guard<std::mutex> lock(dataMutex);
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::minutes(config.cleanupIntervalMinutes);

    for (auto& pair : keyStates) {
        KeyState& state = pair.second;
        TrimPressHistory(state, cutoff);
        TrimHoldHistory(state, cutoff);
    }
}
void KeyToggleMonitor::TrimPressHistory(KeyState& state, const std::chrono::steady_clock::time_point& cutoff) {
    while (!state.pressTimes.empty() && state.pressTimes.front() < cutoff) {
        state.pressTimes.pop_front();
    }

    if (state.pressTimes.size() > config.maxPressHistory) {
        state.pressTimes.erase(
            state.pressTimes.begin(),
            state.pressTimes.begin() + (state.pressTimes.size() - config.maxPressHistory)
        );
    }
}
void KeyToggleMonitor::TrimHoldHistory(KeyState& state, const std::chrono::steady_clock::time_point& cutoff) {
    while (!state.holdTimePoints.empty() && state.holdTimePoints.front() < cutoff) {
        state.holdTimePoints.pop_front();
        if (!state.holdDurations.empty()) {
            state.holdDurations.pop_front();
        }
    }

    while (state.holdDurations.size() > state.holdTimePoints.size()) {
        state.holdDurations.pop_front();
    }
    while (state.holdTimePoints.size() > state.holdDurations.size()) {
        state.holdTimePoints.pop_front();
    }

    if (state.holdDurations.size() > config.maxHoldHistory) {
        state.holdDurations.erase(
            state.holdDurations.begin(),
            state.holdDurations.begin() + (state.holdDurations.size() - config.maxHoldHistory)
        );
        state.holdTimePoints.erase(
            state.holdTimePoints.begin(),
            state.holdTimePoints.begin() + (state.holdTimePoints.size() - config.maxHoldHistory)
        );
    }
}

// Дебаг лог
void KeyToggleMonitor::DebugLogPress(DWORD vkCode, const std::string& action, long long holdTime) const {
    auto it = keyStates.find(vkCode);
    if (it == keyStates.end()) return;

    std::stringstream ss;
    ss << "[LOGEN] Key " << action << ": " << it->second.keyName;

    if (holdTime > 0) {
        ss << " (hold: " << holdTime << "ms)";
    }

    ss << " | Total: " << it->second.totalPresses
        << " | Suspicion: " << std::fixed << std::setprecision(1)
        << (it->second.currentSuspicion * 100) << "%";

    Log(ss.str());
}
std::string KeyToggleMonitor::VirtualKeyToString(DWORD vkCode) {
    switch (vkCode) {
    case VK_INSERT: return "INS";
    case VK_HOME: return "HOME";
    case VK_END: return "END";
    case VK_DELETE: return "DEL";
    case VK_F1: return "F1";
    case VK_F2: return "F2";
    case VK_F3: return "F3";
    case VK_F4: return "F4";
    case VK_F5: return "F5";
    case VK_F6: return "F6";
    case VK_F7: return "F7";
    case VK_F8: return "F8";
    case VK_F9: return "F9";
    case VK_F10: return "F10";
    case VK_F11: return "F11";
    case VK_F12: return "F12";
    case VK_PRIOR: return "PGUP";
    case VK_NEXT: return "PGDN";
    case VK_NUMPAD0: return "NUM0";
    case VK_NUMPAD1: return "NUM1";
    case VK_NUMPAD2: return "NUM2";
    case VK_NUMPAD3: return "NUM3";
    case VK_NUMPAD4: return "NUM4";
    case VK_NUMPAD5: return "NUM5";
    case VK_NUMPAD6: return "NUM6";
    case VK_NUMPAD7: return "NUM7";
    case VK_NUMPAD8: return "NUM8";
    case VK_NUMPAD9: return "NUM9";
    default: return "KEY_" + std::to_string(vkCode);
    }
}
bool KeyToggleMonitor::IsGameWindowActive() {
    return true;
}

// ==================== ПУБЛИЧНЫЕ МЕТОДЫ ====================

int KeyToggleMonitor::GetTotalDetections() const {
    std::lock_guard<std::mutex> lock(dataMutex);
    return globalStats.totalDetections;
}

int KeyToggleMonitor::GetSuspiciousDetections() const {
    std::lock_guard<std::mutex> lock(dataMutex);
    return globalStats.suspiciousDetections;
}

int KeyToggleMonitor::GetTotalKeyEvents() const {
    std::lock_guard<std::mutex> lock(dataMutex);
    return globalStats.totalKeyEvents;
}

int KeyToggleMonitor::GetKeyDetectionCount(DWORD vkCode) const {
    std::lock_guard<std::mutex> lock(dataMutex);
    auto it = globalStats.keyDetectionCounts.find(vkCode);
    if (it != globalStats.keyDetectionCounts.end()) {
        return it->second;
    }
    return 0;
}

std::string KeyToggleMonitor::GetStatsString() const {
    std::lock_guard<std::mutex> lock(dataMutex);

    if (globalStats.totalKeyEvents == 0) {
        return "No key events recorded";
    }

    std::stringstream ss;
    ss << "[LOGEN] Events: " << globalStats.totalKeyEvents
        << ", Detections: " << globalStats.totalDetections
        << " (suspicious: " << globalStats.suspiciousDetections << ")";

    if (!globalStats.patternCounts.empty()) {
        ss << ", Patterns: ";
        bool first = true;
        for (const auto& pair : globalStats.patternCounts) {
            if (!first) ss << ", ";
            ss << pair.first << ":" << pair.second;
            first = false;
        }
    }

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::minutes>(now - globalStats.startTime).count();
    ss << ", Uptime: " << uptime << "min";

    return ss.str();
}

std::string KeyToggleMonitor::GetDetailedStats() const {
    std::lock_guard<std::mutex> lock(dataMutex);

    std::stringstream ss;
    ss << "=== Key Toggle Monitor Detailed Stats ===\n";
    ss << "Total key events: " << globalStats.totalKeyEvents << "\n";
    ss << "Total detections: " << globalStats.totalDetections << "\n";
    ss << "Suspicious detections: " << globalStats.suspiciousDetections << "\n";
    ss << "Pattern detections: " << globalStats.patternDetections << "\n";

    if (!globalStats.patternCounts.empty()) {
        ss << "\nPattern breakdown:\n";
        for (const auto& pair : globalStats.patternCounts) {
            ss << "  " << pair.first << ": " << pair.second << "\n";
        }
    }

    if (!globalStats.keyDetectionCounts.empty()) {
        ss << "\nKey detection breakdown:\n";
        for (const auto& pair : globalStats.keyDetectionCounts) {
            ss << "  " << VirtualKeyToString(pair.first) << ": " << pair.second << "\n";
        }
    }

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::minutes>(now - globalStats.startTime).count();
    ss << "\nUptime: " << uptime << " minutes\n";

    return ss.str();
}

std::map<DWORD, std::string> KeyToggleMonitor::GetKeyStates() const {
    std::lock_guard<std::mutex> lock(dataMutex);

    std::map<DWORD, std::string> result;
    for (const auto& pair : keyStates) {
        std::stringstream ss;
        ss << pair.second.keyName
            << " (presses: " << pair.second.totalPresses
            << ", detections: " << pair.second.suspiciousCount
            << ", suspicion: " << std::fixed << std::setprecision(1)
            << (pair.second.currentSuspicion * 100) << "%)";

        if (pair.second.inCooldown) {
            ss << " [COOLDOWN]";
        }

        result[pair.first] = ss.str();
    }

    return result;
}

bool KeyToggleMonitor::IsRunning() const {
    return isRunning.load();
}

void KeyToggleMonitor::SetPollInterval(int ms) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.pollInterval = ms;
}

void KeyToggleMonitor::AddMonitoredKey(DWORD vkCode) {
    std::lock_guard<std::mutex> lock(dataMutex);

    if (keyStates.find(vkCode) == keyStates.end()) {
        keyStates[vkCode] = KeyState(vkCode, VirtualKeyToString(vkCode));
        config.monitoredKeys.push_back(vkCode);

        if (config.highRiskKeys.find(vkCode) == config.highRiskKeys.end() &&
            config.mediumRiskKeys.find(vkCode) == config.mediumRiskKeys.end() &&
            config.lowRiskKeys.find(vkCode) == config.lowRiskKeys.end()) {
            config.lowRiskKeys.insert(vkCode);
        }
    }
}

void KeyToggleMonitor::RemoveMonitoredKey(DWORD vkCode) {
    std::lock_guard<std::mutex> lock(dataMutex);

    keyStates.erase(vkCode);

    config.monitoredKeys.erase(
        std::remove(config.monitoredKeys.begin(), config.monitoredKeys.end(), vkCode),
        config.monitoredKeys.end()
    );

    config.highRiskKeys.erase(vkCode);
    config.mediumRiskKeys.erase(vkCode);
    config.lowRiskKeys.erase(vkCode);
}

void KeyToggleMonitor::SetLogAllPresses(bool enabled) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.logAllPresses = enabled;
}

void KeyToggleMonitor::SetDetectionThreshold(float threshold) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.highRiskThreshold = threshold;
    config.mediumRiskThreshold = threshold + 0.1f;
    config.lowRiskThreshold = threshold + 0.2f;
}

void KeyToggleMonitor::SetCooldownTime(int seconds) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.cooldownAfterDetectionSec = seconds;
}

void KeyToggleMonitor::ClearAllData() {
    std::lock_guard<std::mutex> lock(dataMutex);

    for (auto& pair : keyStates) {
        pair.second.pressTimes.clear();
        pair.second.holdDurations.clear();
        pair.second.holdTimePoints.clear();
        pair.second.currentSuspicion = 0.0f;
        pair.second.inCooldown = false;
    }
}

void KeyToggleMonitor::ResetStats() {
    std::lock_guard<std::mutex> lock(dataMutex);

    globalStats.totalDetections = 0;
    globalStats.suspiciousDetections = 0;
    globalStats.totalKeyEvents = 0;
    globalStats.patternDetections = 0;
    globalStats.patternCounts.clear();
    globalStats.keyDetectionCounts.clear();
    globalStats.startTime = std::chrono::steady_clock::now();

    for (auto& pair : keyStates) {
        pair.second.totalPresses = 0;
        pair.second.suspiciousCount = 0;
        pair.second.currentSuspicion = 0.0f;
        pair.second.inCooldown = false;
        pair.second.lastDetectionTime = GetMinTimePoint();
    }
}

void KeyToggleMonitor::SetPatternWeights(float recon, float combat, float spam, float regularity) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.reconPatternWeight = recon;
    config.combatPatternWeight = combat;
    config.spamPatternWeight = spam;
    config.regularityWeight = regularity;
}

void KeyToggleMonitor::SetTimeWindows(int reconSec, int combatSec, int spamSec) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.reconWindowSec = reconSec;
    config.combatWindowSec = combatSec;
    config.spamWindowSec = spamSec;
}

void KeyToggleMonitor::SetRiskLevels(const std::vector<DWORD>& highRisk, const std::vector<DWORD>& mediumRisk, const std::vector<DWORD>& lowRisk) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.highRiskKeys.clear();
    config.highRiskKeys.insert(highRisk.begin(), highRisk.end());

    config.mediumRiskKeys.clear();
    config.mediumRiskKeys.insert(mediumRisk.begin(), mediumRisk.end());

    config.lowRiskKeys.clear();
    config.lowRiskKeys.insert(lowRisk.begin(), lowRisk.end());
}

void KeyToggleMonitor::SetHistoryLimits(int maxPressHistory, int maxHoldHistory) {
    std::lock_guard<std::mutex> lock(dataMutex);
    config.maxPressHistory = maxPressHistory;
    config.maxHoldHistory = maxHoldHistory;
}

// ==================== ГЛОБАЛЬНЫЕ ФУНКЦИИ ====================

void StartKeyToggleMonitoring() {
    if (!g_keyMonitor) {
        g_keyMonitor = new KeyToggleMonitor();
    }

    if (!g_keyMonitor->IsRunning()) {
        g_keyMonitor->Start();
    }
}

void StopKeyToggleMonitoring() {
    if (g_keyMonitor) {
        g_keyMonitor->Stop();
        delete g_keyMonitor;
        g_keyMonitor = nullptr;
    }
}

bool IsKeyMonitoringActive() {
    return g_keyMonitor != nullptr && g_keyMonitor->IsRunning();
}

std::string GetKeyMonitorStats() {
    if (g_keyMonitor) {
        return g_keyMonitor->GetStatsString();
    }
    return "KeyMonitor not active";
}

void AddKeyToMonitor(DWORD vkCode) {
    if (g_keyMonitor) {
        g_keyMonitor->AddMonitoredKey(vkCode);
    }
}

void RemoveKeyFromMonitor(DWORD vkCode) {
    if (g_keyMonitor) {
        g_keyMonitor->RemoveMonitoredKey(vkCode);
    }
}

void SetKeyMonitorLogging(bool enabled) {
    if (g_keyMonitor) {
        g_keyMonitor->SetLogAllPresses(enabled);
    }
}