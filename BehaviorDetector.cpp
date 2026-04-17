#define NOMINMAX
#include <Windows.h>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <map>
#include <sstream>
#include <iomanip>
#include "BehaviorDetector.h"
#include "EntityPosSampler.h"
#include "LocalProvider.h"
#include "LogUtils.h"
#include "dllmain.h"
#include "EntityClassifier.h"
#include "DetectionAggregator.h"
// === ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ===
static std::atomic<bool> g_bdRun{ false };
static HANDLE            g_bdThread = nullptr;
static uintptr_t         g_entityArray = 0;
static BDLocalProvider   g_provider = nullptr;
static BDConfig          G{};
BDSuspicionMetrics g_suspicionMetrics;
static BDLocalSnapshot g_prevSnapshot;
static int      s_espEvents = 0;
static uint64_t s_espWindowStartMs = 0;
static uint64_t s_espHoldStartMs = 0;
static bool g_debugMode = false;
static int g_debugCounter = 0;


// === NoRecoil и Bullet детекция ===
static RecoilData g_recoilData;
static std::vector<BulletInfo> g_activeBullets;
static uint64_t g_lastRecoilLog = 0;
static uint64_t g_lastSwayLog = 0;
static uint64_t g_lastBulletLog = 0;
// === NoRecoil и Bullet детекция ===

struct TrackedTarget {
    uint64_t id;
    BDVec3 lastPos;
    float lastAngle;
    uint64_t lastSeenTime;
    int trackingFrames;
    bool hasObstacle;
    std::string entityType;
};
static std::map<uint64_t, TrackedTarget> g_trackedTargets;
static uint64_t g_lastTrackingCleanup = 0;
static std::map<std::string, uint64_t> g_logCooldowns;
static std::map<std::string, int> g_logCounters;
static const uint64_t LOG_COOLDOWN_CHEAT = 60000;
static const uint64_t LOG_COOLDOWN_ESP = 10000;
static const uint64_t LOG_COOLDOWN_DEBUG = 30000;
static const BDConfig AGGRESSION_CONFIGS[] = {
    // LOW
    {
        500, 150.0, 8, 8, 12, 6.0, 0.006, 30.0, 1000.0, 8000.0, 4, 4.0, 0.07,
        BDConfig::LOW,
        { 12.0, 9.0, 7.0 }, { 1500.0, 1000.0, 600.0 }, { 8, 6, 4 }, { 60000.0, 40000.0, 20000.0 },
        3.0, 0.15, 6.0, 18, 35.0, 18.0, 0.25,
        // Новые настройки для LOW
        12.0f, 300.0f, 150.0f, 40.0f,
        25.0f, 50.0f, 8.0f, 7.0f, 12.0f,
        0.5f, 0.3f, 0.2f, 0.8f, 0.4f,
        2.0f, 1.2f, 0.8f,
        12.0f, 400.0f, 6, 4,
        12.0f, 250.0f,
        15.0f, 10.0f,
        200.0f, 120.0f, 100.0f,
        3.0f, 0.5f, 0.5f,
        25.0f, 100.0f, 2.0f, 200.0f, 3.5f, 300.0f, 5.0f
    },
    // MEDIUM
    {
        800, 100.0, 6, 6, 8, 4.0, 0.003, 20.0, 700.0, 5000.0, 3, 3.0, 0.10,
        BDConfig::MEDIUM,
        { 9.0, 6.0, 4.0 }, { 1000.0, 850.0, 400.0  }, { 6, 4, 3 }, { 40000.0, 35000.0, 15000.0 },
        2.0, 0.12, 4.0, 12, 50.0, 15.0, 0.15,
        // Новые настройки для MEDIUM
        15.0f, 400.0f, 200.0f, 35.0f,
        15.0f, 25.0f, 6.0f, 5.0f, 10.0f,
        0.8f, 0.5f, 0.3f, 1.0f, 0.6f,
        2.5f, 1.5f, 1.0f,
        15.0f, 500.0f, 4, 2,
        15.0f, 300.0f,
        15.0f, 8.0f,
        250.0f, 150.0f, 120.0f,
        2.0f, 0.3f, 0.3f,
        20.0f, 80.0f, 1.0f, 150.0f, 2.5f, 250.0f, 4.0f
    },
    // HIGH
    {
        1200, 80.0, 4, 4, 6, 2.5, 0.0015, 8.0, 400.0, 3000.0, 2, 2.5, 0.15,
        BDConfig::HIGH,
        { 7.0, 4.0, 2.5 }, { 800.0, 500.0, 250.0 }, { 5, 3, 2 }, { 30000.0, 20000.0, 10000.0 },
        1.5, 0.10, 3.0, 8, 70.0, 12.0, 0.08,
        // Новые настройки для HIGH
        18.0f, 500.0f, 250.0f, 30.0f,
        10.0f, 15.0f, 4.0f, 3.0f, 8.0f,
        1.2f, 0.8f, 0.5f, 1.5f, 1.0f,
        3.0f, 2.0f, 1.5f,
        18.0f, 600.0f, 3, 1,
        18.0f, 350.0f,
        18.0f, 6.0f,
        300.0f, 200.0f, 150.0f,
        1.5f, 0.2f, 0.2f,
        15.0f, 60.0f, 0.8f, 120.0f, 2.0f, 200.0f, 3.0f
    }
};
static bool IsLivingTarget(const std::string& entityType) {
    return entityType == "Player" || entityType == "Zombie" || entityType == "Animal";
}
static float CalculateDistance(float x1, float y1, float z1, float x2, float y2, float z2) {
    float dx = x2 - x1;
    float dy = y2 - y1;
    float dz = z2 - z1;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
}
static inline uint64_t NowMs() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
static bool CanLog(const std::string& logType, uint64_t cooldownMs) {
    uint64_t currentTime = NowMs();
    auto it = g_logCooldowns.find(logType);
    if (it == g_logCooldowns.end() || currentTime - it->second > cooldownMs) {
        g_logCooldowns[logType] = currentTime;
        g_logCounters[logType] = 0;
        return true;
    }
    g_logCounters[logType]++;
    return false;
}
static bool IsLikelyRealObstacle(const EPS::TargetLOS& entity, float distance) {
    if (distance < G.closeObstacleMaxDistance) {
        return true;
    }

    if (distance < G.mediumObstacleMaxDistance) {
        float objectHeight = entity.pos[1];
        if (objectHeight > G.mediumObstacleMinHeight) {
            return true;
        }
    }

    if (distance >= G.mediumObstacleMaxDistance && distance < G.farObstacleMaxDistance) {
        float objectHeight = entity.pos[1];
        if (objectHeight > G.farObstacleMinHeight) {
            return true;
        }
    }

    if (distance >= G.farObstacleMaxDistance && distance < G.veryFarObstacleMaxDistance) {
        float objectHeight = entity.pos[1];
        if (objectHeight > G.veryFarObstacleMinHeight) {
            return true;
        }
    }

    return false;
}

static bool IsObjectBetween(const BDVec3& from, const BDVec3& to, const BDVec3& obj, float targetDistance) {
    float objDistance = CalculateDistance(from.x, from.y, from.z, obj.x, obj.y, obj.z);
    if (objDistance >= targetDistance) return false;
    if (objDistance < 2.0f) return false;
    BDVec3 lineStartToObj = { obj.x - from.x, obj.y - from.y, obj.z - from.z };
    BDVec3 lineDir = { to.x - from.x, to.y - from.y, to.z - from.z };
    float lineLength = std::sqrt(lineDir.x * lineDir.x + lineDir.y * lineDir.y + lineDir.z * lineDir.z);
    if (lineLength > 0) {
        lineDir.x /= lineLength;
        lineDir.y /= lineLength;
        lineDir.z /= lineLength;
    }
    float projection = lineStartToObj.x * lineDir.x + lineStartToObj.y * lineDir.y + lineStartToObj.z * lineDir.z;
    if (projection < 0) return false;
    BDVec3 closestPoint = {
        from.x + lineDir.x * projection,
        from.y + lineDir.y * projection,
        from.z + lineDir.z * projection
    };
    float distanceToLine = CalculateDistance(obj.x, obj.y, obj.z, closestPoint.x, closestPoint.y, closestPoint.z);
    bool isBetween = (projection > 0 && projection < targetDistance && distanceToLine < 25.0f);
    return isBetween;
}
static inline bool SafeReadPtr(uintptr_t address, uintptr_t& result) {
    if (!IsValidAddress(address)) return false;
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)address, &result, sizeof(result), &bytesRead) && bytesRead == sizeof(result);
}
static inline bool Read32(HANDLE hp, uintptr_t addr, void* out, size_t cb) {
    if (!IsValidAddress(addr)) return false;
    SIZE_T br = 0;
    return ReadProcessMemory(hp, (LPCVOID)addr, out, cb, &br) && br == cb;
}
static inline bool IsLikelyCoord(float v) {
    return std::isfinite(v) && v > -500000.f && v < 500000.f;
}
static bool HasObstacleBetween(const BDVec3& from, const BDVec3& to, const std::vector<EPS::TargetLOS>& allTargets, std::string& obstacleType, uint64_t targetId = 0) {
    float distance = CalculateDistance(from.x, from.y, from.z, to.x, to.y, to.z);

    if (distance > 500.0f) {
        obstacleType = "TooFar";
        return false;
    }
    if (distance < G.minObstacleDistance) {
        obstacleType = "None";
        return false;
    }
    BDVec3 direction = {
        to.x - from.x,
        to.y - from.y,
        to.z - from.z
    };
    float dirLength = std::sqrt(direction.x * direction.x + direction.y * direction.y + direction.z * direction.z);
    if (dirLength > 0) {
        direction.x /= dirLength;
        direction.y /= dirLength;
        direction.z /= dirLength;
    }

    int obstacleCount = 0;
    for (const auto& potentialObstacle : allTargets) {
        if (potentialObstacle.id == targetId) continue;
        if (potentialObstacle.isLiving) continue;

        BDVec3 obstaclePos = { potentialObstacle.pos[0], potentialObstacle.pos[1], potentialObstacle.pos[2] };
        float obstacleDist = CalculateDistance(from.x, from.y, from.z, obstaclePos.x, obstaclePos.y, obstaclePos.z);

        if (obstacleDist > G.maxObstacleDistance) continue;
        if (obstacleDist > distance) continue;
        if (obstacleDist < 2.0f) continue;

        float height = obstaclePos.y - from.y;
        if (height < 0.3f) continue;

        BDVec3 toObstacle = { obstaclePos.x - from.x, obstaclePos.y - from.y, obstaclePos.z - from.z };
        float projection = (toObstacle.x * direction.x + toObstacle.y * direction.y + toObstacle.z * direction.z);

        BDVec3 perpendicular = {
            toObstacle.x - direction.x * projection,
            toObstacle.y - direction.y * projection,
            toObstacle.z - direction.z * projection
        };
        float perpendicularDist = std::sqrt(perpendicular.x * perpendicular.x + perpendicular.y * perpendicular.y + perpendicular.z * perpendicular.z);

        if (projection > 1.0f && projection < (distance - 1.0f) &&
            perpendicularDist < 15.0f &&
            height >= 0.3f) {

            if (IsLikelyRealObstacle(potentialObstacle, obstacleDist)) {
                obstacleCount++;
            }
        }
    }
    static uint64_t lastStaticCheck = 0;
    static std::vector<uintptr_t> cachedStaticObjects;

    uint64_t now = NowMs();
    if (now - lastStaticCheck > 10000) {
        lastStaticCheck = now;
        cachedStaticObjects.clear();
        uintptr_t worldPtr = EPS::GetWorldPtr();
        if (worldPtr) {
            uintptr_t world = 0;
            if (SafeReadPtr(worldPtr, world) && world) {
                cachedStaticObjects = EPS::GetStaticObjects(world);
            }
        }
    }
    if (!cachedStaticObjects.empty()) {
        HANDLE self = GetCurrentProcess();

        for (uintptr_t staticObj : cachedStaticObjects) {
            float objPos[3] = { 0 };
            bool hasValidPos = false;

            BDVec3 obstaclePos = { 0, 0, 0 };
            uintptr_t vs = 0;
            if (SafeReadPtr(staticObj + OFFSET_WORLD_VISUALSTATE, vs) && vs) {
                if (Read32(self, vs + 0x20, objPos, sizeof(float) * 3)) {
                    if (IsLikelyCoord(objPos[0]) && IsLikelyCoord(objPos[1]) && IsLikelyCoord(objPos[2])) {
                        obstaclePos = { objPos[0], objPos[1], objPos[2] };
                        hasValidPos = true;
                    }
                }
            }

            if (hasValidPos) {
                float objDistance = CalculateDistance(from.x, from.y, from.z, obstaclePos.x, obstaclePos.y, obstaclePos.z);

                if (objDistance > 500.0f) continue;
                if (objDistance > distance) continue;
                if (objDistance < 2.0f) continue;

                if (IsObjectBetween(from, to, obstaclePos, distance)) {
                    obstacleCount++;
                }
            }
        }
    }

    if (obstacleCount > 0) {
        obstacleType = "Obstacles(" + std::to_string(obstacleCount) + ")";
        return true;
    }
    float camPos[3], camFwd[3];
    std::string targetType = "Unknown";
    for (const auto& target : allTargets) {
        if (target.id == targetId) {
            targetType = target.entityType;
            break;
        }
    }

    if (targetType != "Obstacle") {
        if (LP_GetCamera(camPos, camFwd)) {
            BDVec3 viewDir = { camFwd[0], camFwd[1], camFwd[2] };
            BDVec3 toTarget = { to.x - from.x, to.y - from.y, to.z - from.z };

            float toTargetLength = std::sqrt(toTarget.x * toTarget.x + toTarget.y * toTarget.y + toTarget.z * toTarget.z);
            if (toTargetLength > 0) {
                toTarget.x /= toTargetLength;
                toTarget.y /= toTargetLength;
                toTarget.z /= toTargetLength;
            }

            float dotProduct = viewDir.x * toTarget.x + viewDir.y * toTarget.y + viewDir.z * toTarget.z;
            float angle = std::acos(std::max(-1.0f, std::min(1.0f, dotProduct))) * 57.2958f;

            if (distance > 80.0f && angle < 1.5f) {
                obstacleType = "Heuristic";
                return true;
            }
        }
    }

    obstacleType = "None";
    return false;
}

static float AnalyzeTrackingSmoothness(uint64_t targetId, const BDVec3& currentPos, float currentAngle, const BDLocalSnapshot& local) {
    auto it = g_trackedTargets.find(targetId);
    if (it == g_trackedTargets.end()) return 0.0f;

    TrackedTarget& tracked = it->second;
    float posDelta = CalculateDistance(tracked.lastPos.x, tracked.lastPos.y, tracked.lastPos.z,
        currentPos.x, currentPos.y, currentPos.z);
    float angleDelta = std::abs(currentAngle - tracked.lastAngle);

    float smoothnessScore = 0.0f;

    if (posDelta > 2.0f && angleDelta < 1.0f) {
        smoothnessScore += 1.0f;
    }

    if (!tracked.hasObstacle && tracked.trackingFrames > 60) {
        smoothnessScore += 0.5f;
    }

    if (tracked.hasObstacle && angleDelta < 0.5f && tracked.trackingFrames > 30) {
        smoothnessScore += 1.5f;
    }

    tracked.lastPos = currentPos;
    tracked.lastAngle = currentAngle;
    tracked.trackingFrames++;

    return smoothnessScore;
}
static void UpdateTargetTracking(const std::vector<EPS::TargetLOS>& allTargets, const BDLocalSnapshot& local) {
    uint64_t currentTime = NowMs();

    if (currentTime - g_lastTrackingCleanup > 10000) {
        for (auto it = g_trackedTargets.begin(); it != g_trackedTargets.end();) {
            if (currentTime - it->second.lastSeenTime > 30000) {
                it = g_trackedTargets.erase(it);
            }
            else {
                ++it;
            }
        }
        g_lastTrackingCleanup = currentTime;
    }

    for (const auto& target : allTargets) {
        if (!IsLivingTarget(target.entityType) ||
            target.angDeg >= G.maxTargetAngle ||
            target.dist >= G.maxTargetDistance) {
            continue;
        }

        BDVec3 targetPos = { target.pos[0], target.pos[1], target.pos[2] };
        BDVec3 playerPos = { local.pos.x, local.pos.y, local.pos.z };

        std::string obstacleType;
        bool hasObstacle = HasObstacleBetween(playerPos, targetPos, allTargets, obstacleType);

        auto it = g_trackedTargets.find(target.id);
        if (it != g_trackedTargets.end()) {
            TrackedTarget& tracked = it->second;
            tracked.lastSeenTime = currentTime;
            tracked.hasObstacle = hasObstacle;

            float trackingScore = AnalyzeTrackingSmoothness(target.id, targetPos, target.angDeg, local);
            if (trackingScore > 0) {
                g_suspicionMetrics.aimbotScore += trackingScore * 0.3f;
                g_suspicionMetrics.espScore += trackingScore * 0.05f;

                if (g_suspicionMetrics.espScore + g_suspicionMetrics.aimbotScore >= 40.0f) {
                    g_detectionAggregator.NotifyDangerousPlayer(target.id);
                }
            }
        }
        else {
            g_trackedTargets[target.id] = {
                target.id,
                targetPos,
                target.angDeg,
                currentTime,
                1,
                hasObstacle,
                target.entityType
            };
        }
    }
}
static void BD_DebugTestTriggers(const BDLocalSnapshot& local, const std::vector<EPS::TargetLOS>& targets, uint64_t nowMs) {
    if (!g_debugMode) return;
    g_debugCounter++;
}
static void BD_DetectUnnaturalBehavior(const std::vector<EPS::TargetLOS>& allTargets, const BDLocalSnapshot& local, uint64_t nowMs) {
    static std::vector<uint64_t> recentBehaviorEvents;

    recentBehaviorEvents.erase(
        std::remove_if(recentBehaviorEvents.begin(), recentBehaviorEvents.end(),
            [nowMs](uint64_t time) { return nowMs - time > 30000; }),
        recentBehaviorEvents.end()
    );

    int suspiciousEventsLast30s = recentBehaviorEvents.size();

    if (suspiciousEventsLast30s > 20) {
        float frequencyScore = suspiciousEventsLast30s * 0.5f;
        g_suspicionMetrics.espScore += frequencyScore;
        g_detectionAggregator.NotifyDangerousPlayer(0ULL);  
    }

    int currentSuspiciousTargets = 0;
    for (const auto& target : allTargets) {
        if (!IsLivingTarget(target.entityType) ||
            target.angDeg >= G.maxTargetAngle ||
            target.dist >= G.maxTargetDistance) {
            continue;
        }
        if (IsLivingTarget(target.entityType) && target.angDeg < G.unnaturalAngle) {

            BDVec3 playerPos = { local.pos.x, local.pos.y, local.pos.z };
            BDVec3 targetPos = { target.pos[0], target.pos[1], target.pos[2] };
            std::string obstacleType;
            bool hasObstacle = HasObstacleBetween(playerPos, targetPos, allTargets, obstacleType, target.id);

            if (hasObstacle && target.angDeg < 15.0f && target.dist <= G.unnaturalDistance) {
                currentSuspiciousTargets++;
            }
        }
    }

    if (currentSuspiciousTargets > 0) {
        recentBehaviorEvents.push_back(nowMs);
    }
}
static void BD_DetectPerfectKnowledge(const std::vector<EPS::TargetLOS>& allTargets, const BDLocalSnapshot& local, uint64_t nowMs) {
    int invisibleTargets = 0;
    int totalLivingTargets = 0;

    for (const auto& target : allTargets) {
        if (!IsLivingTarget(target.entityType) ||
            target.angDeg >= G.maxTargetAngle ||
            target.dist >= G.maxTargetDistance) {
            continue;
        }
        if (IsLivingTarget(target.entityType) &&
            target.angDeg < G.perfectKnowledgeAngle &&
            target.dist <= G.perfectKnowledgeDistance) {

            totalLivingTargets++;
            BDVec3 playerPos = { local.pos.x, local.pos.y, local.pos.z };
            BDVec3 targetPos = { target.pos[0], target.pos[1], target.pos[2] };
            std::string obstacleType;
            bool hasObstacle = HasObstacleBetween(playerPos, targetPos, allTargets, obstacleType, target.id);

            if (hasObstacle) {
                invisibleTargets++;
            }
        }
    }

    if (totalLivingTargets >= G.perfectKnowledgeMinTargets &&
        invisibleTargets >= G.perfectKnowledgeMinInvisible) {
        float knowledgeRatio = (float)invisibleTargets / totalLivingTargets;
        if (knowledgeRatio > 0.3f) {
            float knowledgeScore = (invisibleTargets * 6.0f) + (totalLivingTargets * 3.0f);
            g_suspicionMetrics.espScore += knowledgeScore * 0.2f;
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);  
        }
    }
}
static void BD_DetectESPPatterns(const std::vector<EPS::TargetLOS>& visibleTargets, const std::vector<EPS::TargetLOS>& allTargets, const BDLocalSnapshot& local, uint64_t nowMs) {
    g_suspicionMetrics.suspiciousActions.erase(
        std::remove_if(g_suspicionMetrics.suspiciousActions.begin(),
            g_suspicionMetrics.suspiciousActions.end(),
            [nowMs](uint64_t time) { return nowMs - time > 60000; }),
        g_suspicionMetrics.suspiciousActions.end()
    );

    UpdateTargetTracking(allTargets, local);

    bool foundActualTarget = false;
    EPS::TargetLOS actualTarget{};
    float bestPriority = -1.0f;
    for (const auto& target : allTargets) {
        if (!IsLivingTarget(target.entityType) ||
            target.angDeg >= G.maxTargetAngle ||
            target.dist >= G.maxTargetDistance) {
            continue;
        }
        float priority = 0.0f;
        if (target.entityType == "Player") {
            priority = 1000.0f - target.angDeg;
        }
        else if (target.entityType == "Zombie") {
            priority = 500.0f - target.angDeg;
        }
        else if (target.entityType == "Animal") {
            priority = 100.0f - target.angDeg;
        }

        if (priority > bestPriority) {
            bestPriority = priority;
            actualTarget = target;
            foundActualTarget = true;
        }
    }
    if (!foundActualTarget) {
        return;
    }
    auto trackIt1 = g_trackedTargets.find(actualTarget.id);
    if (trackIt1 == g_trackedTargets.end() || trackIt1->second.trackingFrames < 30) {
        return;
    }

    const auto& target = actualTarget;

    // ВЫЧИСЛИТЬ hasObstacle ОДИН РАЗ
    BDVec3 playerPos = { local.pos.x, local.pos.y, local.pos.z };
    BDVec3 targetPos = { target.pos[0], target.pos[1], target.pos[2] };
    std::string obstacleType;
    bool hasObstacle = HasObstacleBetween(playerPos, targetPos, allTargets, obstacleType, target.id);

    // Логирование (используем уже вычисленное hasObstacle)
    static uint64_t lastTargetLog = 0;
    if (nowMs - lastTargetLog > 1500) {
        lastTargetLog = nowMs;
        // hasObstacle уже вычислено - ничего не делаем, т.к. логирование закомментировано
    }

    static uint64_t lastDebug = 0;
    if (nowMs - lastDebug > 3000) {
        lastDebug = nowMs;
        // Log(("[LOGEN] Selected target: " + target.entityType + " Angle: " + std::to_string(target.angDeg) + "° Dist: " + std::to_string(target.dist) + "m" + " Priority: " + std::to_string(bestPriority)).c_str());
    }

    float behaviorMultiplier = 1.0f;
    if (!IsLivingTarget(target.entityType)) {
        behaviorMultiplier = 0.3f;
    }
    else {
        if (target.entityType == "Player") behaviorMultiplier = G.multiplierPlayer;
        else if (target.entityType == "Zombie") behaviorMultiplier = G.multiplierZombie;
        else if (target.entityType == "Animal") behaviorMultiplier = G.multiplierAnimal;
    }

    bool suspiciousBehavior = false;
    std::string behaviorReason = "";

    auto trackIt = g_trackedTargets.find(target.id);
    static uint64_t lastQuickDetection = 0;

    if (trackIt != g_trackedTargets.end()) {
        TrackedTarget& tracked = trackIt->second;

        if (hasObstacle && tracked.trackingFrames > G.quickTrackingFrames && target.angDeg < G.instantAimAngle && target.dist < G.trackingDistance) {
            suspiciousBehavior = true;
            behaviorReason = "Instant_Wallhack_Targeting";
        }
        else if (hasObstacle && tracked.trackingFrames > G.longTrackingFrames && target.dist < G.trackingDistance) {
            suspiciousBehavior = true;
            behaviorReason = "Tracking_Through_Obstacle";
        }
    }

    if (local.fired && hasObstacle && target.angDeg < G.shootingAngle && target.dist < G.shootingDistance) {
        suspiciousBehavior = true;
        behaviorReason = "Shooting_Through_Wall";
    }

    if (hasObstacle && target.angDeg < G.preciseAimAngle && target.dist < G.preciseAimDistance) {
        suspiciousBehavior = true;
        behaviorReason = "Precise_Aiming_At_Invisible";
    }

    if (suspiciousBehavior) {
        float behaviorScore = 0.0f;
        if (behaviorReason == "Instant_Wallhack_Targeting") {
            behaviorScore = 1.0f * behaviorMultiplier;
        }
        else if (behaviorReason == "Tracking_Through_Obstacle") {
            behaviorScore = 0.8f * behaviorMultiplier;   // 0.3 * 2.5 = 0.75
        }
        else if (behaviorReason == "Shooting_Through_Wall") {
            behaviorScore = 1.5f * behaviorMultiplier;  // 0.5 * 2.5 = 1.25
        }
        else if (behaviorReason == "Precise_Aiming_At_Invisible") {
            behaviorScore = 0.8f * behaviorMultiplier;  // 0.3 * 2.5 = 0.75
        }
        g_suspicionMetrics.espScore += behaviorScore;
        g_suspicionMetrics.wallhackScore += behaviorScore * 0.8f;
        g_suspicionMetrics.totalFlags++;

        std::string obstacleDisplay = hasObstacle ? "Obstacle" : "None";

        std::string cooldownKey = "BEHAVIOR_" + target.entityType + "_" + behaviorReason;
        if (CanLog(cooldownKey, 2000)) {
            if (target.entityType == "Player") {
                std::stringstream ss;
                ss << "[VEH] ESP_LOOK_AT_INVISIBLE | " << behaviorReason
                    << " | Target: " << target.entityType
                    << " | Obstacle: " << obstacleDisplay
                    << " | Dist: " << std::fixed << std::setprecision(1) << target.dist << "m"
                    << " | Angle: " << std::fixed << std::setprecision(1) << target.angDeg << "°"
                    << " Visible: " << (!hasObstacle ? "Y" : "N")
                    << " | TrackFrames: " << (trackIt != g_trackedTargets.end() ? trackIt->second.trackingFrames : 0)
                    << " | Multiplier: " << std::fixed << std::setprecision(1) << behaviorMultiplier << "x"
                    << " | ESP+: " << std::fixed << std::setprecision(1) << behaviorScore;
               // Log(ss.str().c_str());
               // StartSightImgDetection("[VEH] ESP_LOOK_AT_INVISIBLE | " + behaviorReason + " | Target: " + target.entityType + "|Dist: " + std::to_string(target.dist) + "m");
                g_detectionAggregator.NotifyDangerousPlayer(target.id ? target.id : 0ULL);
            }
        }
    }

    BD_DetectPerfectKnowledge(allTargets, local, nowMs);
    BD_DetectUnnaturalBehavior(allTargets, local, nowMs);
}
static void BD_DetectAimbotSmoothness(const BDLocalSnapshot& current, const BDLocalSnapshot& previous) {
    static float prevYaw = 0;
    static float prevPitch = 0;
    static bool hasPrevious = false;

    if (!hasPrevious) {
        prevYaw = current.yaw;
        prevPitch = current.pitch;
        hasPrevious = true;
        return;
    }

    float yawDelta = std::abs(current.yaw - prevYaw);
    float pitchDelta = std::abs(current.pitch - prevPitch);

    if (yawDelta > 0.5f && yawDelta < G.aimbotSmoothnessThreshold) {
        g_suspicionMetrics.aimbotScore += (0.5 - G.aggressionLevel * 0.1);
    }

    if (pitchDelta > 0.5f && pitchDelta < G.aimbotSmoothnessThreshold) {
        g_suspicionMetrics.aimbotScore += (0.5 - G.aggressionLevel * 0.1);
    }

    prevYaw = current.yaw;
    prevPitch = current.pitch;
}
static void BD_DetectSpeedhack(const BDLocalSnapshot& current, uint64_t deltaMs) {
    static BDVec3 prevPos = { 0, 0, 0 };
    static uint64_t prevTime = 0;

    if (prevTime == 0) {
        prevPos = current.pos;
        prevTime = NowMs();
        return;
    }

    float deltaTime = deltaMs / 1000.0f;
    if (deltaTime < 0.05f) return;

    float dx = current.pos.x - prevPos.x;
    float dy = current.pos.y - prevPos.y;
    float dz = current.pos.z - prevPos.z;
    float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
    float velocity = distance / deltaTime;

    if (velocity > G.speedhackVelocityThreshold) {
        g_suspicionMetrics.speedhackScore += (2.0 - G.aggressionLevel);
        g_suspicionMetrics.totalFlags++;
    }

    prevPos = current.pos;
    prevTime = NowMs();
}
static void BD_DetectSuperhumanReaction(const BDLocalSnapshot& current, const std::vector<EPS::TargetLOS>& targets, uint64_t nowMs) {
    static uint64_t lastTargetChange = 0;
    static uint64_t lastEnemySpotted = 0;
    static int lastTargetCount = 0;
    static uint64_t lastValidInteraction = 0;
    static int superhumanCounter = 0;

    int currentTargetCount = 0;
    for (const auto& target : targets) {
        if (IsLivingTarget(target.entityType) && target.angDeg < G.superhumanAngle) {
            currentTargetCount++;
        }
    }

    BDLocalSnapshot local;
    if (g_provider(local)) {
        bool isPlayerActive = (local.ads || local.fired || std::abs(local.yaw - g_prevSnapshot.yaw) > 2.0f);

        if (!isPlayerActive && currentTargetCount != lastTargetCount) {
            lastTargetCount = currentTargetCount;
            return;
        }

        if (isPlayerActive) {
            lastValidInteraction = nowMs;
        }
    }

    if (currentTargetCount > lastTargetCount && lastEnemySpotted > 0 &&
        nowMs - lastValidInteraction < 5000 &&
        superhumanCounter < 2) {

        uint64_t reactionTime = nowMs - lastEnemySpotted;
        int maxReactionTime = 150 - G.aggressionLevel * 30;

        if (reactionTime < maxReactionTime && reactionTime > 25) {
            superhumanCounter++;
            g_suspicionMetrics.aimbotScore += (2.0 - G.aggressionLevel * 0.3);
        }
    }

    if (currentTargetCount == lastTargetCount && nowMs - lastEnemySpotted > 2000) {
        superhumanCounter = 0;
    }

    if (currentTargetCount > 0) {
        lastEnemySpotted = nowMs;
    }

    if (lastTargetChange > 0 && currentTargetCount != lastTargetCount) {
        uint64_t switchTime = nowMs - lastTargetChange;
        int minSwitchTime = 100 - G.aggressionLevel * 20;

        if (switchTime < minSwitchTime) {
            g_suspicionMetrics.aimbotScore += (1.0 - G.aggressionLevel * 0.2);
        }
        lastTargetChange = nowMs;
    }

    lastTargetCount = currentTargetCount;
}
static void BD_DetectTriggerbot(const BDLocalSnapshot& current, const std::vector<EPS::TargetLOS>& targets, uint64_t nowMs) {
    static uint64_t lastShotTime = 0;
    static uint64_t lastTargetAcquisition = 0;

    EPS::TargetLOS actualTarget{};
    bool foundTarget = false;

    for (const auto& target : targets) {
        if (IsLivingTarget(target.entityType) &&
            target.angDeg < G.triggerbotAngle &&
            target.dist < 150.0f) {
            actualTarget = target;
            foundTarget = true;
            break;
        }
    }

    if (current.fired && foundTarget) {
        if (lastTargetAcquisition > 0) {
            uint64_t reactionTime = nowMs - lastTargetAcquisition;
            int maxReactionTime = 80 - G.aggressionLevel * 20;

            if (reactionTime < maxReactionTime) {
                g_suspicionMetrics.triggerbotScore += (2.0 - G.aggressionLevel * 0.3);
            }
        }
        lastShotTime = nowMs;
    }

    if (foundTarget && actualTarget.angDeg < 8.0f) {
        lastTargetAcquisition = nowMs;
    }
}
static void BD_AnalyzeSuspicionMetrics()
{
    static uint64_t lastAnalysisTime = 0;
    static uint64_t lastForceReset = 0;
    uint64_t currentTime = NowMs();

    // Принудительный полный сброс каждые 90 секунд
    if (currentTime - lastForceReset > 90000) {
        g_suspicionMetrics = BDSuspicionMetrics{};
        g_trackedTargets.clear();
        lastForceReset = currentTime;
        return;
    }

    int analysisInterval = 20000;
    if (currentTime - lastAnalysisTime < analysisInterval) return;
    lastAnalysisTime = currentTime;

    double totalScore = g_suspicionMetrics.espScore +
        g_suspicionMetrics.aimbotScore +
        g_suspicionMetrics.speedhackScore +
        g_suspicionMetrics.wallhackScore +
        g_suspicionMetrics.triggerbotScore;

    std::string cheatType = "UNKNOWN";
    double maxScore = 0.0;

    if (g_suspicionMetrics.espScore > maxScore && g_suspicionMetrics.espScore > 15.0) {
        maxScore = g_suspicionMetrics.espScore; cheatType = "ESP";
    }
    if (g_suspicionMetrics.aimbotScore > maxScore && g_suspicionMetrics.aimbotScore > 12.0) {
        maxScore = g_suspicionMetrics.aimbotScore; cheatType = "AIMBOT";
    }
    if (g_suspicionMetrics.wallhackScore > maxScore && g_suspicionMetrics.wallhackScore > 10.0) {
        maxScore = g_suspicionMetrics.wallhackScore; cheatType = "WALLHACK";
    }
    if (g_suspicionMetrics.triggerbotScore > maxScore && g_suspicionMetrics.triggerbotScore > 8.0) {
        maxScore = g_suspicionMetrics.triggerbotScore; cheatType = "TRIGGERBOT";
    }
    if (g_suspicionMetrics.speedhackScore > maxScore && g_suspicionMetrics.speedhackScore > 8.0) {
        maxScore = g_suspicionMetrics.speedhackScore; cheatType = "SPEEDHACK";
    }

    double scoreThreshold = G.suspiciousScoreThreshold * 2.0;
    int flagsThreshold = (10 - G.aggressionLevel * 2) * 5;

    // Мало подозрений — мягкий decay и выход
    if (maxScore < 15.0) {
        double softDecay = 0.9;
        g_suspicionMetrics.espScore *= softDecay;
        g_suspicionMetrics.aimbotScore *= softDecay;
        g_suspicionMetrics.speedhackScore *= softDecay;
        g_suspicionMetrics.wallhackScore *= softDecay;
        g_suspicionMetrics.triggerbotScore *= softDecay;

        if (g_suspicionMetrics.espScore < 10.0 && g_suspicionMetrics.aimbotScore < 10.0) {
            g_suspicionMetrics = BDSuspicionMetrics{};
        }
        return;
    }

    // Основная проверка
    if (totalScore > scoreThreshold || g_suspicionMetrics.totalFlags > flagsThreshold) {
        if (CanLog("CHEAT_DETECTION", LOG_COOLDOWN_CHEAT)) {
            BDLocalSnapshot currentLocal;
            if (g_provider(currentLocal)) {
                if (currentLocal.pitch > 80.0f || currentLocal.pitch < -80.0f) {
                    return;
                }
            }

            // ← Всё логирование и скриншот теперь делает NotifyDangerousPlayer
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);

            // Мягкий decay (на High уже сбросит Notify, так что безопасно)
            g_suspicionMetrics.espScore *= 0.1;
            g_suspicionMetrics.aimbotScore *= 0.1;
            g_suspicionMetrics.wallhackScore *= 0.1;
            g_suspicionMetrics.triggerbotScore *= 0.1;
            g_suspicionMetrics.speedhackScore *= 0.1;
        }
    }

    // Защита от переполнения скора
    const double MAX_ESP_SCORE = 80.0;
    const double MAX_AIMBOT_SCORE = 40.0;
    const double MAX_WALLHACK_SCORE = 50.0;

    g_suspicionMetrics.espScore = std::min(g_suspicionMetrics.espScore, MAX_ESP_SCORE);
    g_suspicionMetrics.aimbotScore = std::min(g_suspicionMetrics.aimbotScore, MAX_AIMBOT_SCORE);
    g_suspicionMetrics.wallhackScore = std::min(g_suspicionMetrics.wallhackScore, MAX_WALLHACK_SCORE);
}
static void BD_ESP_Tick(uintptr_t entityArray, uint64_t nowMs) {
    float camPos[3], camFwd[3];
    if (!LP_GetCamera(camPos, camFwd)) {
        s_espHoldStartMs = 0;
        return;
    }

    auto ents = EPS::Snapshot(entityArray);

    std::vector<EPS::TargetLOS> bucket;
    EPS::EPS_BuildLOSBucket(ents, camPos, camFwd, bucket, 50);

    if (!bucket.empty()) {
        const auto& closest = bucket.front();
        if (closest.dist < 20.0f) {
            return; 
        }
        if (closest.dist > 2.0f && closest.dist < 500.0f) {
            BDLocalSnapshot local;
            if (g_provider(local)) {
                BD_DebugTestTriggers(local, bucket, nowMs);
                BD_DetectESPPatterns(bucket, bucket, local, nowMs);
                BD_DetectAimbotSmoothness(local, g_prevSnapshot);
                BD_DetectSpeedhack(local, 16);
                BD_DetectSuperhumanReaction(local, bucket, nowMs);
                BD_DetectTriggerbot(local, bucket, nowMs);
                BD_AnalyzeSuspicionMetrics();
                g_prevSnapshot = local;
            }
        }
    }

    int level = (int)G.aggressionLevel;
    if (level < 0) level = 0;
    if (level > 2) level = 2;

    double currentAngleThreshold = G.espAngleThreshold[level];
    double currentInvisibleGraceMs = G.espInvisibleGraceMs[level];
    int currentEventsForAlert = G.espEventsForAlert[level];
    double currentWindowMs = G.espWindowMs[level];

    if (bucket.empty()) {
        s_espHoldStartMs = 0;
        return;
    }

    const auto& t = bucket.front();
    BDVec3 from = { camPos[0], camPos[1], camPos[2] };
    BDVec3 to = { t.pos[0], t.pos[1], t.pos[2] };
    std::string obstacleType;
    bool hasObstacle = HasObstacleBetween(from, to, bucket, obstacleType, t.id);
    const bool isInvisible = hasObstacle;

    if (t.angDeg < currentAngleThreshold && isInvisible) {
        if (s_espHoldStartMs == 0) s_espHoldStartMs = nowMs;
        if (nowMs - s_espHoldStartMs >= (uint64_t)currentInvisibleGraceMs) {
            if (s_espWindowStartMs == 0 || nowMs - s_espWindowStartMs > (uint64_t)currentWindowMs) {
                s_espWindowStartMs = nowMs;
                s_espEvents = 0;
            }
            s_espEvents++;
            s_espHoldStartMs = 0;

            if (s_espEvents >= currentEventsForAlert) {
                s_espWindowStartMs = nowMs;
                s_espEvents = 0;
            }
        }
    }
    else {
        s_espHoldStartMs = 0;
    }
}
void BD_ApplySmartReset() {
    static uint64_t lastSmartReset = 0;
    static uint64_t lastFrameDecay = 0;
    static uint64_t lastLogCooldownCleanup = 0;
    uint64_t currentTime = NowMs();

    // 1. БЫСТРЫЙ DECAY КАЖДЫЕ 2 СЕКУНДЫ (без изменений)
    if (currentTime - lastFrameDecay > 2000) {
        lastFrameDecay = currentTime;
        float frameDecay = 0.85f;
        g_suspicionMetrics.espScore *= frameDecay;
        g_suspicionMetrics.aimbotScore *= frameDecay;
        g_suspicionMetrics.wallhackScore *= frameDecay;
        g_suspicionMetrics.triggerbotScore *= frameDecay;
        g_suspicionMetrics.speedhackScore *= frameDecay;

        // Лимиты
        g_suspicionMetrics.espScore = std::min(g_suspicionMetrics.espScore, (double)50.0);
        g_suspicionMetrics.aimbotScore = std::min(g_suspicionMetrics.aimbotScore, (double)30.0);
        g_suspicionMetrics.wallhackScore = std::min(g_suspicionMetrics.wallhackScore, (double)40.0);
        g_suspicionMetrics.triggerbotScore = std::min(g_suspicionMetrics.triggerbotScore, (double)25.0);
        g_suspicionMetrics.speedhackScore = std::min(g_suspicionMetrics.speedhackScore, (double)20.0);
    }

    // 2. ОЧИСТКА LOG COOLDOWNS (10)
    if (currentTime - lastLogCooldownCleanup > 600000) { // 10 минут
        lastLogCooldownCleanup = currentTime;
        uint64_t cutoff = currentTime - 600000; // Удаляем записи старше 10 минут

        size_t beforeSize = g_logCooldowns.size();
        for (auto it = g_logCooldowns.begin(); it != g_logCooldowns.end(); ) {
            if (it->second < cutoff) {
                g_logCounters.erase(it->first);
                it = g_logCooldowns.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    // 3. АВТО-СБРОС ПРИ АНОМАЛИЯХ (без изменений)
    if (g_suspicionMetrics.espScore > 80.0f ||
        g_suspicionMetrics.aimbotScore > 50.0f ||
        g_suspicionMetrics.totalFlags > 100) {
        g_detectionAggregator.NotifyDangerousPlayer(0ULL);
        g_suspicionMetrics = BDSuspicionMetrics{};
        lastSmartReset = currentTime;
        return;
    }

    // 4. ПЛАНОВЫЙ СБРОС (5)
    if (currentTime - lastSmartReset > 300000) { // 5 минуты
        g_suspicionMetrics = BDSuspicionMetrics{};
        g_trackedTargets.clear();
        g_activeBullets.clear();
        g_logCooldowns.clear();
        g_logCounters.clear();
        g_recoilData = RecoilData{};
        lastSmartReset = currentTime;
    }
}
static DWORD WINAPI BD_PumpThread(LPVOID) {
    uint64_t lastTickTime = NowMs();

    while (g_bdRun.load()) {
        const uint64_t nowMs = NowMs();
        uint64_t deltaMs = nowMs - lastTickTime;
        lastTickTime = nowMs;

        BD_ApplySmartReset();

        if (g_provider) {
            BDLocalSnapshot snap{};
            if (!g_provider(snap)) {
            }
        }

        if (IsValidAddress(g_entityArray)) {
            BD_ESP_Tick(g_entityArray, nowMs);
            uintptr_t worldPtr = EPS::GetWorldPtr();
            if (worldPtr) {
                uintptr_t world = 0;
                if (SafeReadPtr(worldPtr, world) && world) {
                    BD_DetectNoRecoil(g_prevSnapshot, nowMs);
                    BD_AnalyzeBullets(world, g_prevSnapshot, nowMs);
                }
            }
        }

        int sleepTime = 8 - G.aggressionLevel * 4;
        Sleep(sleepTime);
    }

    return 0;
}
static void BD_AdjustSettingsForMap() {
    float worldSize = EPS::EPS_GetWorldSize();
    std::string worldName = EPS::EPS_GetWorldName();

    if (worldSize > 20000.0f) {
        G.wallhackTraceDistance = 90.0f;
        G.speedhackVelocityThreshold = 30.0f;
        G.espPerfectKnowledgeAngle = 5.0f;
    }
    else if (worldSize > 15000.0f) {
        G.wallhackTraceDistance = 70.0f;
        G.speedhackVelocityThreshold = 25.0f;
        G.espPerfectKnowledgeAngle = 4.0f;
    }
    else if (worldSize > 12000.0f) {
        G.wallhackTraceDistance = 50.0f;
        G.speedhackVelocityThreshold = 18.0f;
        G.espPerfectKnowledgeAngle = 3.0f;
    }
    else {
        G.wallhackTraceDistance = 35.0f;
        G.speedhackVelocityThreshold = 12.0f;
        G.espPerfectKnowledgeAngle = 2.0f;
    }

    if (worldName.find("namalsk") != std::string::npos) {
        G.speedhackVelocityThreshold = 22.0f;
        G.espSuspiciousActionsPerMinute = 12;
    }
    else if (worldName.find("deerisle") != std::string::npos) {
        G.wallhackTraceDistance = 65.0f;
    }
    else if (worldName.find("alteria") != std::string::npos || worldName.find("iztek") != std::string::npos) {
        G.wallhackTraceDistance = 40.0f;
        G.speedhackVelocityThreshold = 14.0f;
        G.espSuspiciousActionsPerMinute = 22;
    }
    else if (worldName.find("esseker") != std::string::npos) {
        G.wallhackTraceDistance = 45.0f;
    }
    else if (worldName.find("melkart") != std::string::npos || worldName.find("valning") != std::string::npos) {
        G.wallhackTraceDistance = 100.0f;
        G.speedhackVelocityThreshold = 35.0f;
    }
    else if (worldName.find("onforin") != std::string::npos) {
        G.wallhackTraceDistance = 120.0f;
        G.speedhackVelocityThreshold = 40.0f;
        G.espPerfectKnowledgeAngle = 6.0f;
    }
    else if (worldName.find("enoch") != std::string::npos) {
        G.wallhackTraceDistance = 65.0f;
        G.espSuspiciousActionsPerMinute = 18;
        G.speedhackVelocityThreshold = 16.0f;
    }
    else if (worldName.find("chernarus") != std::string::npos) {
        G.wallhackTraceDistance = 60.0f;
        G.speedhackVelocityThreshold = 20.0f;
        G.espPerfectKnowledgeAngle = 3.5f;
        G.espSuspiciousActionsPerMinute = 12;
    }
}
void BD_Init(const BDConfig& cfg) {
    int level = (int)cfg.aggressionLevel;
    if (level < 0) level = 0;
    if (level > 2) level = 2;

    G = AGGRESSION_CONFIGS[level];
    BD_AdjustSettingsForMap();
}
bool BD_StartPump(uintptr_t entityArray, BDLocalProvider provider) {
    if (!IsValidAddress(entityArray)) {
        return false;
    }

    if (g_bdRun.exchange(true)) {
        return true;
    }

    g_entityArray = entityArray;
    g_provider = provider;

    g_bdThread = CreateThread(nullptr, 0, BD_PumpThread, nullptr, 0, nullptr);
    if (!g_bdThread) {
        g_bdRun.store(false);
        return false;
    }

    return true;
}
void BD_StopPump() {
    if (!g_bdRun.exchange(false)) return;

    if (g_bdThread) {
        WaitForSingleObject(g_bdThread, 3000);
        CloseHandle(g_bdThread);
        g_bdThread = nullptr;
    }

    g_suspicionMetrics = BDSuspicionMetrics{};
    s_espEvents = 0;
    s_espWindowStartMs = 0;
    s_espHoldStartMs = 0;
    g_trackedTargets.clear();
}
void BD_SetAggressionLevel(BDConfig::AggressionLevel level) {
    BD_StopPump();

    int newLevel = (int)level;
    if (newLevel < 0) newLevel = 0;
    if (newLevel > 2) newLevel = 2;

    G = AGGRESSION_CONFIGS[newLevel];

    if (g_entityArray && g_provider) {
        BD_StartPump(g_entityArray, g_provider);
    }
}
BDConfig::AggressionLevel BD_GetAggressionLevel() {
    return G.aggressionLevel;
}
void BD_GetSuspicionMetrics(BDSuspicionMetrics& outMetrics) {
    outMetrics = g_suspicionMetrics;
}
void BD_ResetSuspicionMetrics() {
    g_suspicionMetrics = BDSuspicionMetrics{};
    g_trackedTargets.clear();

    // Сброс новых данных
    g_recoilData = RecoilData{};
    g_activeBullets.clear();
    g_lastRecoilLog = 0;
    g_lastSwayLog = 0;
    g_lastBulletLog = 0;
}

void BD_ClearLogData() {
    g_logCooldowns.clear();
    g_logCounters.clear();
}

void BD_DetectNoRecoil(const BDLocalSnapshot& local, uint64_t nowMs) {
    static uint64_t lastRecoilCheck = 0;
    if (nowMs - lastRecoilCheck < 100) return;
    lastRecoilCheck = nowMs;

    uintptr_t localPlayer = 0;
    uintptr_t worldPtr = EPS::GetWorldPtr();
    if (!worldPtr) return;

    uintptr_t world = 0;
    if (!SafeReadPtr(worldPtr, world) || !world) return;

    if (!SafeReadPtr(world + OFFSET_LOCALPLAYER_PTR, localPlayer) || !localPlayer) {
        return;
    }

    uintptr_t itemInHands = 0;
    if (!SafeReadPtr(localPlayer + OFFSET_PLAYER_ITEMINHANDS, itemInHands) || !itemInHands) {
        g_recoilData.baseRecoil = 0.0f;
        return;
    }

    std::string className = EntityClassifier::TryReadClassName(itemInHands);
    if (className.empty() || className.find("Weapon") == std::string::npos) {
        g_recoilData.baseRecoil = 0.0f;
        return;
    }

    float currentRecoil = 0.0f;
    float weaponSway = 0.01f;

    uintptr_t weaponInfo = 0;
    if (SafeReadPtr(itemInHands + OFFSET_WEAPON_INFOTABLE, weaponInfo) && weaponInfo) {
        Read32(GetCurrentProcess(), weaponInfo + 0x50, &g_recoilData.baseRecoil, sizeof(float));
        uintptr_t skeleton = 0;
        if (SafeReadPtr(localPlayer + OFFSET_DAYZPLAYER_SKELETON, skeleton) && skeleton) {
            uintptr_t animClass = 0;
            if (SafeReadPtr(skeleton + OFFSET_SKELETON_ANIMCLASS1, animClass) && animClass) {               
                Read32(GetCurrentProcess(), animClass + 0x120, &weaponSway, sizeof(float));
            }
        }
    }

    if (local.fired && g_recoilData.baseRecoil > 0.1f) {
        float expectedRecoil = g_recoilData.baseRecoil * 0.8f;
        float recoilReduction = 0.0f;

        if (g_recoilData.baseRecoil > 0) {
            recoilReduction = (g_recoilData.baseRecoil - currentRecoil) / g_recoilData.baseRecoil;
        }

        if (recoilReduction > 0.9f && g_recoilData.baseRecoil > 0.3f) {
            g_suspicionMetrics.aimbotScore += 2.0f;
            g_suspicionMetrics.totalFlags++;

            if (nowMs - g_lastRecoilLog > 10000) {
                g_lastRecoilLog = nowMs;
                g_detectionAggregator.NotifyDangerousPlayer(0ULL);
               // Log(("[VEH] [NORECOIL] Suspicious recoil reduction: " + std::to_string((int)(recoilReduction * 100)) + "% | Base: " + std::to_string(g_recoilData.baseRecoil)).c_str());
               // StartSightImgDetection(("[VEH] [NORECOIL] Suspicious recoil reduction: " + std::to_string((int)(recoilReduction * 100)) + "% | Base: " + std::to_string(g_recoilData.baseRecoil)).c_str());
               // Log("[LOGEN] SCREENSHOT_CAPTURED | NORECOIL detection");
            }
        }
    }
    if (local.ads && weaponSway < 0.001f && g_recoilData.baseRecoil > 0.3f) {
        g_suspicionMetrics.aimbotScore += 1.5f;
        g_suspicionMetrics.totalFlags++;

        if (nowMs - g_lastSwayLog > 15000) {
            g_lastSwayLog = nowMs;
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);
           // Log(("[VEH] [NOSWAY] Zero weapon sway detected | Sway: " + std::to_string(weaponSway)).c_str());
           // StartSightImgDetection(("[VEH] [NOSWAY] Zero weapon sway detected | Sway: " + std::to_string(weaponSway)).c_str());
           // Log("[LOGEN] SCREENSHOT_CAPTURED | NOSWAY detection");
        }
    }
}
static inline bool ReadPtr(HANDLE hp, uintptr_t addr, uintptr_t& out) {
    if (!IsValidAddress(addr)) return false;
    SIZE_T br = 0;
    return ReadProcessMemory(hp, (LPCVOID)addr, &out, sizeof(out), &br) && br == sizeof(out);
}
void BD_AnalyzeBullets(uintptr_t world, const BDLocalSnapshot& local, uint64_t nowMs) {
    static uint64_t lastBulletCheck = 0;
    if (nowMs - lastBulletCheck < 50) return;
    lastBulletCheck = nowMs;

    uintptr_t bulletList = 0;
    if (!ReadPtr(GetCurrentProcess(), world + OFFSET_WORLD_BULLETLIST, bulletList) || !bulletList) {
        return;
    }

    std::vector<BulletInfo> currentBullets;

    for (int i = 0; i < 50; i++) {
        uintptr_t bullet = 0;
        uintptr_t addr = bulletList + (i * 0x18);

        if (ReadPtr(GetCurrentProcess(), addr, bullet) && bullet && IsValidAddress(bullet)) {
            BulletInfo info;
            info.id = bullet;
            Read32(GetCurrentProcess(), bullet + 0x20, &info.startPos.x, sizeof(float) * 3);
            Read32(GetCurrentProcess(), bullet + 0x30, &info.velocity.x, sizeof(float) * 3);
            bool isValidBullet = true;
            if (!IsLikelyCoord(info.startPos.x) || !IsLikelyCoord(info.startPos.y) || !IsLikelyCoord(info.startPos.z)) {
                isValidBullet = false;
            }
            info.speed = std::sqrt(info.velocity.x * info.velocity.x +
                info.velocity.y * info.velocity.y +
                info.velocity.z * info.velocity.z);

            if (info.speed < 10.0f || info.speed > 1500.0f) {
                isValidBullet = false;
            }
            if (info.startPos.y < -100.0f || info.startPos.y > 5000.0f) {
                isValidBullet = false;
            }

            if (!isValidBullet) {
                continue; 
            }

            info.spawnTime = nowMs;
            currentBullets.push_back(info);
            if (info.speed > 1000.0f) { // Более 1000 м/с - подозрительно
                g_suspicionMetrics.aimbotScore += 1.5f; // Меньший штраф
                g_suspicionMetrics.totalFlags++;

                if (nowMs - g_lastBulletLog > 15000) { // Увеличили кулдаун
                    g_lastBulletLog = nowMs;
                    g_detectionAggregator.NotifyDangerousPlayer(info.id ? info.id : 0ULL);
                   // Log(("[VEH] [BULLET_HACK] Suspicious bullet speed: " + std::to_string((int)info.speed) + " m/s").c_str());
                   // StartSightImg2(("[VEH] [BULLET_HACK] Suspicious bullet speed: " + std::to_string((int)info.speed) + " m/s").c_str());
                }
            }
        }
    }

    g_activeBullets = currentBullets;
}
bool BD_IsBulletGoingThroughWalls(const BulletInfo& bullet, const BDVec3& targetPos, uintptr_t world) {
    BDVec3 bulletDir = {
        bullet.velocity.x / bullet.speed,
        bullet.velocity.y / bullet.speed,
        bullet.velocity.z / bullet.speed
    };

    BDVec3 toTarget = {
        targetPos.x - bullet.startPos.x,
        targetPos.y - bullet.startPos.y,
        targetPos.z - bullet.startPos.z
    };

    float targetDist = CalculateDistance(bullet.startPos.x, bullet.startPos.y, bullet.startPos.z,
        targetPos.x, targetPos.y, targetPos.z);

    if (targetDist < 5.0f) return false; // Слишком близко

    // Нормализуем вектор к цели
    float toTargetLength = std::sqrt(toTarget.x * toTarget.x + toTarget.y * toTarget.y + toTarget.z * toTarget.z);
    if (toTargetLength > 0) {
        toTarget.x /= toTargetLength;
        toTarget.y /= toTargetLength;
        toTarget.z /= toTargetLength;
    }

    float dotProduct = bulletDir.x * toTarget.x + bulletDir.y * toTarget.y + bulletDir.z * toTarget.z;

    // Если пуля направлена точно на цель (97% точность)
    if (dotProduct > 0.97f && targetDist > 20.0f) {
        std::string obstacleType;
        return HasObstacleBetween(bullet.startPos, targetPos, std::vector<EPS::TargetLOS>(), obstacleType);
    }

    return false;
}