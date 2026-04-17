#pragma once
#include <vector>
#include <functional>
#include <string>
#include <atomic>
#include <mutex>

struct BDVec3 {
    float x, y, z;
    BDVec3(float x = 0, float y = 0, float z = 0) : x(x), y(y), z(z) {}
};
struct BDEnemy {
    int id;
    BDVec3 pos;
    bool alive;
    std::string name;
};
struct BDConfig {
    // Основные лимиты
    size_t maxEntries = 800;
    double aimbotReactionMs = 120.0;
    int    aimbotCountThreshold = 6;
    int    wallhackCountThreshold = 6;
    int    norecoilCountThreshold = 10;
    double aimAngleThresholdDeg = 3.0;
    double smoothnessThreshold = 0.002;
    double suspiciousScoreThreshold = 20.0;
    double recentVisibleGraceMs = 600.0;
    double fastAimWindowMs = 5000.0;
    double fastAimMinCount = 3;
    double speedZThreshold = 3.5;
    double speedEwmaAlpha = 0.10;

    enum AggressionLevel {
        LOW = 0,
        MEDIUM = 1,
        HIGH = 2
    };
    AggressionLevel aggressionLevel = MEDIUM;

    // ESP настройки для каждого уровня агрессии
    double espAngleThreshold[3] = { 10.0, 7.0, 5.0 };
    double espInvisibleGraceMs[3] = { 1000.0, 700.0, 400.0 };
    int espEventsForAlert[3] = { 5, 3, 2 };
    double espWindowMs[3] = { 45000.0, 30000.0, 15000.0 };

    // Новые члены
    double espLookAtInvisibleTime = 2.0;
    double espTargetSwitchSpeed = 0.1;
    double espPerfectKnowledgeAngle = 3.0;
    int espSuspiciousActionsPerMinute = 15;
    double wallhackTraceDistance = 50.0;
    double speedhackVelocityThreshold = 15.0;
    double aimbotSmoothnessThreshold = 0.15;

    // === УВЕЛИЧЕННЫЕ ДИСТАНЦИИ ===
    float maxTargetAngle = 15.0f;
    float maxTargetDistance = 500.0f;        // УВЕЛИЧЕНО: было 400
    float maxObstacleDistance = 300.0f;      // УВЕЛИЧЕНО: было 200
    float perpendicularTolerance = 35.0f;

    // Пороги детекции
    float quickTrackingFrames = 15.0f;
    float longTrackingFrames = 25.0f;
    float instantAimAngle = 6.0f;
    float preciseAimAngle = 5.0f;
    float shootingAngle = 10.0f;

    // Очки за детекцию

    float scoreInstantAim = 0.05f;    // было 0.1f
    float scoreQuickTracking = 0.04f; // было 0.08f  
    float scoreLongTracking = 0.025f; // было 0.05f
    float scoreShootingWall = 0.15f;  // было 0.3f
    float scorePreciseAim = 0.075f;   // было 0.15f

    float multiplierPlayer = 1.0f; 
    float multiplierZombie = 0.8f;
    float multiplierAnimal = 0.6f;

    // Настройки для других функций
    float perfectKnowledgeAngle = 15.0f;
    float perfectKnowledgeDistance = 800.0f;  // УВЕЛИЧЕНО: было 500
    int perfectKnowledgeMinTargets = 4;
    int perfectKnowledgeMinInvisible = 2;

    float unnaturalAngle = 15.0f;
    float unnaturalDistance = 600.0f;         // УВЕЛИЧЕНО: было 300

    float superhumanAngle = 15.0f;
    float triggerbotAngle = 8.0f;

    // Дистанции для разных типов детекции - УВЕЛИЧЕНО
    float trackingDistance = 400.0f;          // УВЕЛИЧЕНО: было 250
    float shootingDistance = 300.0f;          // УВЕЛИЧЕНО: было 150
    float preciseAimDistance = 250.0f;        // УВЕЛИЧЕНО: было 120

    // Настройки фильтрации препятствий
    float minObstacleDistance = 20.0f;
    float minObstacleHeight = 0.5f;           // УВЕЛИЧЕНО: игнорируем объекты ниже 0.5м
    float minProjectionDistance = 0.3f;

    // Настройки IsLikelyRealObstacle - УВЕЛИЧЕНО
    float closeObstacleMaxDistance = 50.0f;    // УВЕЛИЧЕНО: было 20
    float mediumObstacleMaxDistance = 200.0f;  // УВЕЛИЧЕНО: было 80
    float mediumObstacleMinHeight = 1.0f;
    float farObstacleMaxDistance = 400.0f;     // УВЕЛИЧЕНО: было 150
    float farObstacleMinHeight = 2.5f;
    float veryFarObstacleMaxDistance = 500.0f; // УВЕЛИЧЕНО: было 250
    float veryFarObstacleMinHeight = 4.0f;
};
struct BDLocalSnapshot {
    float yaw = 0, pitch = 0;
    BDVec3 pos{ 0,0,0 };
    bool fired = false;
    int weaponId = 0;
    bool ads = false;
    int stance = 0;
    int pingMs = 0;
};
struct BDSuspicionMetrics {
    double espScore = 0.0;
    double aimbotScore = 0.0;
    double speedhackScore = 0.0;
    double wallhackScore = 0.0;
    double triggerbotScore = 0.0;
    int totalFlags = 0;
    std::vector<uint64_t> suspiciousActions;
    uint64_t lastDetectionTime = 0;

    std::string GetDetectionReason() const {
        if (espScore > aimbotScore && espScore > speedhackScore && espScore > wallhackScore)
            return "ESP";
        if (aimbotScore > espScore && aimbotScore > speedhackScore && aimbotScore > wallhackScore)
            return "AIMBOT";
        if (speedhackScore > espScore && speedhackScore > aimbotScore && speedhackScore > wallhackScore)
            return "SPEEDHACK";
        if (wallhackScore > espScore && wallhackScore > aimbotScore && wallhackScore > speedhackScore)
            return "WALLHACK";
        return "MULTICHEAT";
    }
};
using BDLocalProvider = std::function<bool(BDLocalSnapshot&)>;

void BD_Init(const BDConfig& cfg = BDConfig());
bool BD_StartPump(uintptr_t entityArrayAddr, BDLocalProvider provider);
void BD_StopPump();
void BD_SetAggressionLevel(BDConfig::AggressionLevel level);
BDConfig::AggressionLevel BD_GetAggressionLevel();
void BD_GetSuspicionMetrics(BDSuspicionMetrics& outMetrics);
void BD_ResetSuspicionMetrics();
void BD_ApplySmartReset();

struct RecoilData {
    float baseRecoil = 0.0f;
    float currentRecoil = 0.0f;
    float swayAmount = 0.01f;
    uint64_t lastShotTime = 0;
    bool isFiring = false;
    std::string currentWeapon;
};
struct BulletInfo {
    uint64_t id;
    BDVec3 startPos;
    BDVec3 velocity;
    float speed;
    uint64_t spawnTime;
};
void BD_ClearLogData();
void BD_DetectNoRecoil(const BDLocalSnapshot& local, uint64_t nowMs);
void BD_AnalyzeBullets(uintptr_t world, const BDLocalSnapshot& local, uint64_t nowMs);
bool BD_IsBulletGoingThroughWalls(const BulletInfo& bullet, const BDVec3& targetPos, uintptr_t world);