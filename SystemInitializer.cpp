#define NOMINMAX
#include <Windows.h>
#include <thread>
#include "SystemInitializer.h"
#include "LogUtils.h"
#include "LocalProvider.h"
#include "EntityPosSampler.h"
#include "StabilityMonitor.h"
#include "BehaviorDetector.h"
#include "GlobalDefines.h"
#include "dllmain.h"

extern StabilityMonitor g_globalStabilityMonitor;
void StartEssentialMonitors();
// === ЗАМЕНИ ЭТУ ФУНКЦИЮ ЦЕЛИКОМ ===
bool InitializeSystemsWithStability(uintptr_t world, uintptr_t entityArray) {
    Log("[LOGEN] [SYSTEM] Starting system initialization...");

    if (!IsValidAddress(world) || !IsValidAddress(entityArray)) {
        Log("[LOGEN] [CRITICAL] Invalid world or entity array addresses");
        return false;
    }

    LP_SetWorld(world);
    LP_ValidateWorldPointer(world);

    if (EPS::DetectWorldNameFromProcess()) {
        float worldSize = EPS::EPS_GetWorldSize();
        std::string worldName = EPS::EPS_GetWorldName();
        bool isZeroBased = LP_IsZeroBasedMap(worldName);

        LogFormat("[LOGEN] [SYSTEM] Map: %s | Size: %.0f | CoordSystem: %s", worldName.c_str(), worldSize, isZeroBased ? "ZERO-BASED" : "CENTERED");
    }

    float testCamPos[3], testCamFwd[3];
    if (LP_GetCameraWithRetry(testCamPos, testCamFwd, 5)) {
        Log("[LOGEN] [SYSTEM] Camera: OK");
        g_globalStabilityMonitor.ReportCameraSuccess();
    }
    else {
        Log("[LOGEN] [WARNING] Camera system issues - using fallback");
        g_globalStabilityMonitor.ReportCameraFailure();
    }

    // Запуск EPS
    if (!EPS::Start(entityArray)) {
        Log("[LOGEN] [CRITICAL] EPS failed to start");
        return false;
    }
    Log("[LOGEN] [SYSTEM] EPS: Started");

    StartEssentialMonitors();

    // === BehaviorDetector ТОЛЬКО в полном режиме ===
    if (!GameProjectMinimal) {
        BDConfig cfg;
        cfg.aggressionLevel = BDConfig::MEDIUM;
        BD_Init(cfg);

        if (BD_StartPump(entityArray, GetLocalSnapshot)) {
            Log("[LOGEN] [SYSTEM] Behavior detection: Started (FULL mode)");
        }
    }
    else {
        Log("[LOGEN] [SYSTEM] Minimal mode: BehaviorDetector DISABLED (zero memory growth)");
        BD_StopPump(); // на всякий случай
    }

    Log("[LOGEN] [SYSTEM] Initialization completed successfully");
    return true;
}

// === ЗАМЕНИ ЭТУ ФУНКЦИЮ ЦЕЛИКОМ (добавлена очистка памяти каждые 5 минут) ===
void StartEssentialMonitors() {
    std::thread([]() {
        int consecutiveFailures = 0;
        const int MAX_FAILURES = 10;
        int healthCheckCount = 0;

        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(60));

            healthCheckCount++;

            // === ПРИНУДИТЕЛЬНАЯ ОЧИСТКА ПАМЯТИ КАЖДЫЕ 5 МИНУТ ===
            if (healthCheckCount % 5 == 0) {
                if (GameProjectMinimal) {
                    BD_ClearLogData();
                    BD_ResetSuspicionMetrics();
                }

                // Принудительно отдаём память Windows
                SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
                Log("[LOGEN] [MEMORY] Forced cleanup performed");
            }

            // ПРОВЕРКА EPS (остальной код без изменений)
            if (!EPS::IsRunning()) {
                consecutiveFailures++;

                if (consecutiveFailures >= MAX_FAILURES) {
                    Log("[LOGEN] [CRITICAL] EPS not running - attempting recovery");

                    uintptr_t currentArray = g_globalEntityArray.load();
                    if (currentArray && IsValidAddress(currentArray)) {
                        EPS::CleanupMemory(false);
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        auto snapshot = EPS::GetLastSnapshot();
                        if (!snapshot.empty()) {
                            consecutiveFailures = 0;
                            Log("[LOGEN] [SYSTEM] EPS recovery completed");
                        }
                    }
                }
                continue;
            }

            auto snapshot = EPS::GetLastSnapshot();
            static auto lastDataTime = std::chrono::steady_clock::now();

            if (!snapshot.empty()) {
                lastDataTime = std::chrono::steady_clock::now();
                consecutiveFailures = 0;
            }
            else {
                auto timeSinceData = std::chrono::steady_clock::now() - lastDataTime;
                if (timeSinceData > std::chrono::seconds(60)) {
                    consecutiveFailures++;
                    if (consecutiveFailures >= 3) {
                        Log("[LOGEN] [SYSTEM] No entity data for 60+ seconds, cleaning up");
                        EPS::CleanupMemory(false);
                        lastDataTime = std::chrono::steady_clock::now();
                        consecutiveFailures = 0;
                    }
                }
            }
            if (healthCheckCount % 10 == 0) {
                LogFormat("[LOGEN] [STATUS] EPS: %s | Data available: %s | Consecutive failures: %d",
                    EPS::IsRunning() ? "RUNNING" : "STOPPED",
                    snapshot.empty() ? "NO" : "YES",
                    consecutiveFailures);
            }
        }
        }).detach();
}