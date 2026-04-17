#pragma once
#include <atomic>
#include <chrono>
#include <string>

class StabilityMonitor {
private:
    std::atomic<int> cameraFailures_{ 0 };
    std::atomic<int> entitySamplingFailures_{ 0 };
    std::atomic<int> renderingFailures_{ 0 };
    std::atomic<int> recoveryAttempts_{ 0 };

    std::chrono::steady_clock::time_point lastRecoveryTime_{};
    std::chrono::steady_clock::time_point startTime_{};
    static constexpr int MAX_CAMERA_FAILURES = 100;     // было 30
    static constexpr int MAX_ENTITY_FAILURES = 500;     // было 50
    static constexpr int RECOVERY_COOLDOWN_MS = 30000;  // уменьшить кд

public:
    StabilityMonitor();

    void ReportCameraFailure();
    void ReportCameraSuccess();
    void ReportEntitySamplingFailure();
    void ReportEntitySamplingSuccess();
    void ReportRenderingFailure();

    bool ShouldAttemptRecovery();
    void RecordRecoveryAttempt();

    std::string GetStatusReport() const;
    void Reset();

private:
    bool IsRecoveryCooldownActive() const;
};
extern StabilityMonitor g_globalStabilityMonitor;
extern std::atomic<int> g_cameraFailures;
extern std::atomic<uintptr_t> g_entityArray;