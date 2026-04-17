#include "DetectionAggregator.h"
#include "BehaviorDetector.h"        
#include "LogUtils.h"
#include "dllmain.h"
#include "GlobalDefines.h"
DetectionAggregator g_detectionAggregator;
void DetectionAggregator::NotifyDangerousPlayer(uint64_t entityId)
{
    if (entityId == 0 || entityId > 0x7FFFFFFFFFFFULL) { 
        return;
    }
    float currentScore = g_suspicionMetrics.espScore +
        g_suspicionMetrics.aimbotScore +
        g_suspicionMetrics.speedhackScore +
        g_suspicionMetrics.wallhackScore +
        g_suspicionMetrics.triggerbotScore +
        (g_suspicionMetrics.totalFlags * 5.0);
    PlayerRiskLevel level = (currentScore >= 120.0f) ? PlayerRiskLevel::High :
        (currentScore >= 40.0f) ? PlayerRiskLevel::Medium :
        PlayerRiskLevel::Low;

    if (level == PlayerRiskLevel::Low) return;

    std::string levelStr = (level == PlayerRiskLevel::High) ? "HIGH RISK" : "MEDIUM RISK";

   // LogFormat("[VEH] Entity %llu → %s (score: %.1f)", entityId, levelStr.c_str(), currentScore);

    if (level == PlayerRiskLevel::High)
    {
        LogFormat("[VEH] Entity %llu — Warning!", entityId);
        StartSightImgDetection(("[VEH] Entity " + std::to_string(entityId) + " — Warning!").c_str());
        BD_ResetSuspicionMetrics();    
    }
}