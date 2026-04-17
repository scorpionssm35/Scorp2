#include "StabilityMonitor.h"
#include "LogUtils.h"
#include "EntityPosSampler.h"

StabilityMonitor g_globalStabilityMonitor;
std::atomic<int> g_cameraFailures{ 0 };
std::atomic<uintptr_t> g_globalEntityArray{ 0 };
StabilityMonitor::StabilityMonitor() : startTime_(std::chrono::steady_clock::now()) {
    lastRecoveryTime_ = startTime_;
}
void StabilityMonitor::ReportCameraFailure() {
    int failures = ++cameraFailures_;
    if (failures % 3 == 0) {
        //LogFormat("[LOGEN] StabilityMonitor: Camera failures: %d/%d", failures, MAX_CAMERA_FAILURES);

        if (failures >= MAX_CAMERA_FAILURES / 2) {
           // Log("[LOGEN] StabilityMonitor: Attempting camera system reset...");
            g_cameraFailures.store(0);
            cameraFailures_.store(0);
        }
    }
}
void StabilityMonitor::ReportCameraSuccess() {
    if (cameraFailures_.load() > 0) {
       // LogFormat("[LOGEN] StabilityMonitor: Camera recovered after %d failures", cameraFailures_.load());
        cameraFailures_.store(0);
    }
}
void StabilityMonitor::ReportEntitySamplingFailure() {
    int failures = ++entitySamplingFailures_;
    if (failures % 50 == 0) {
       // LogFormat("[LOGEN] StabilityMonitor: Entity sampling failures: %d/%d", failures, MAX_ENTITY_FAILURES);
    }
    bool shouldRecover = (failures >= MAX_ENTITY_FAILURES) ||
        (failures >= MAX_ENTITY_FAILURES / 2 && failures % 100 == 0);

    if (shouldRecover) {
        if (IsRecoveryCooldownActive()) {
            if (failures % 100 == 0) { 
               // Log("[LOGEN] StabilityMonitor: Recovery cooldown active");
            }
            return;
        }

       // Log("[LOGEN] StabilityMonitor: Triggering entity sampling recovery");
        RecordRecoveryAttempt();

        uintptr_t currentArray = g_globalEntityArray.load();
        if (currentArray && IsValidAddress(currentArray)) {
            EPS::PerformEntitySamplingRecovery(currentArray);
        }
    }
}
void StabilityMonitor::ReportEntitySamplingSuccess() {
    if (entitySamplingFailures_.load() > 0) {
       // LogFormat("[LOGEN] StabilityMonitor: Entity sampling recovered after %d failures", entitySamplingFailures_.load());
        entitySamplingFailures_.store(0);
    }
}
void StabilityMonitor::ReportRenderingFailure() {
    int failures = ++renderingFailures_;
    if (failures % 5 == 0) {
       // LogFormat("[LOGEN] StabilityMonitor: Rendering failures: %d", failures);
    }
}
bool StabilityMonitor::ShouldAttemptRecovery() {
    if (IsRecoveryCooldownActive()) {
        return false;
    }

    bool cameraCritical = cameraFailures_.load() >= MAX_CAMERA_FAILURES;
    bool entityCritical = entitySamplingFailures_.load() >= MAX_ENTITY_FAILURES;

    return cameraCritical || entityCritical;
}
void StabilityMonitor::RecordRecoveryAttempt() {
    lastRecoveryTime_ = std::chrono::steady_clock::now();
    ++recoveryAttempts_;

    // Сброс счетчиков после восстановления
    cameraFailures_.store(0);
    entitySamplingFailures_.store(0);
    renderingFailures_.store(0);

   // LogFormat("[LOGEN] StabilityMonitor: Recovery attempt #%d recorded", recoveryAttempts_.load());
}
std::string StabilityMonitor::GetStatusReport() const {
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::minutes>(now - startTime_);

    char buffer[512];
    snprintf(buffer, sizeof(buffer),
        "Stability Status (Uptime: %lldmin) - Camera: %d/%d, Entities: %d/%d, Rendering: %d, Recovery: %d",
        uptime.count(),
        cameraFailures_.load(), MAX_CAMERA_FAILURES,
        entitySamplingFailures_.load(), MAX_ENTITY_FAILURES,
        renderingFailures_.load(),
        recoveryAttempts_.load());
    return std::string(buffer);
}
void StabilityMonitor::Reset() {
    cameraFailures_.store(0);
    entitySamplingFailures_.store(0);
    renderingFailures_.store(0);
    recoveryAttempts_.store(0);
    lastRecoveryTime_ = std::chrono::steady_clock::now();
}
bool StabilityMonitor::IsRecoveryCooldownActive() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastRecoveryTime_).count();
    return elapsed < RECOVERY_COOLDOWN_MS;
}