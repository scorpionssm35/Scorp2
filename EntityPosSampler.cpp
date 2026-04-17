#define NOMINMAX
#include "EntityPosSampler.h"
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#include "LogUtils.h"
#include <mutex>
#include "LocalProvider.h"
#include "StabilityMonitor.h"
#include "GlobalDefines.h"
#include "EntityClassifier.h"
#include <set>
#include <map>
#include "dllmain.h"

extern StabilityMonitor g_stabilityMonitor;
extern StabilityMonitor g_globalStabilityMonitor;
StabilityMonitor g_stabilityMonitor;

static std::string g_worldName = "unknown";
static std::mutex g_worldNameMutex;

#ifndef EPS_AUTODETECT_SLOTS
#   define EPS_AUTODETECT_SLOTS  1024
#endif

#ifndef EPS_MAX_ENTRIES_SCAN
#   define EPS_MAX_ENTRIES_SCAN  2048
#endif

#ifndef EPS_POLL_MS
#   define EPS_POLL_MS           16
#endif

std::atomic<float> g_playerX{ 0.0f };
std::atomic<float> g_playerY{ 0.0f };
std::atomic<float> g_playerZ{ 0.0f };

static int AutoDetectPosOffsetFound = 0;
static int AutoDetectPosOffsetTesting = 0;
static int Stablesampling = 0;
static int g_CollectNowWithRecoveryfound = 0;
const int LOG_EVERY_N = 15;

static std::atomic<bool>      g_epsRun{ false };
static HANDLE                 g_epsThread = nullptr;
static std::atomic<uintptr_t> g_epsEntityArray{ 0 };
static std::atomic<uintptr_t> g_posOffset{ 0 };
static std::chrono::steady_clock::time_point g_lastLog{};

static std::atomic<float> g_worldSize{ 15360.0f };
static std::atomic<bool>  g_worldSizeLocked{ false };
static std::atomic<bool>  g_worldSizeGuessed{ false };

static std::vector<EPS::SimpleEntity> g_lastSnapshot;
static std::mutex g_snapshotMutex;
static int g_getLastSnapshotCalls = 0;
static int g_snapshotUpdates = 0;
static int g_snapshotDebugId = 0;

static inline bool ReadPtr(HANDLE hp, uintptr_t addr, uintptr_t& out) {
    if (!IsValidAddress(addr)) return false;
    SIZE_T br = 0;
    return ReadProcessMemory(hp, (LPCVOID)addr, &out, sizeof(out), &br) && br == sizeof(out);
}
static inline bool Read32(HANDLE hp, uintptr_t addr, void* out, size_t cb) {
    if (!IsValidAddress(addr)) return false;
    SIZE_T br = 0;
    return ReadProcessMemory(hp, (LPCVOID)addr, out, cb, &br) && br == cb;
}
static inline bool Read3(HANDLE hp, uintptr_t addr, float out[3]) {
    return Read32(hp, addr, out, sizeof(float) * 3);
}
static inline bool IsLikelyCoord(float v) {
    return std::isfinite(v) && v > -500000.f && v < 500000.f;
}
static inline std::string tolower_str(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}
static inline bool str_contains_ci(const std::string& hay, const std::string& needle) {
    auto H = tolower_str(hay);
    auto N = tolower_str(needle);
    return H.find(N) != std::string::npos;
}
static inline float Clamp01(float v) {
    if (v < -1.0f) return -1.0f;
    if (v > 1.0f) return  1.0f;
    return v;
}
float CalculateDistance(float x1, float y1, float z1, float x2, float y2, float z2) {
    float dx = x2 - x1;
    float dz = z2 - z1;
    return std::sqrt(dx * dx + dz * dz);
}
static bool TryReadVec3(HANDLE hp, uintptr_t base, uintptr_t off, float out[3]) {
    if (!IsValidAddress(base) || off == 0) return false;
    if (!Read3(hp, base + off, out)) return false;
    return IsLikelyCoord(out[0]) && IsLikelyCoord(out[1]) && IsLikelyCoord(out[2]);
}
static bool IsValidPosition(float x, float y, float z) {
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) {
        return false;
    }

    if (fabsf(x) < 0.1f && fabsf(z) < 0.1f) {
        return false;
    }

    std::string worldName = EPS::EPS_GetWorldName();
    float worldSize = EPS::EPS_GetWorldSize();
    bool isZeroBased = LP_IsZeroBasedMap(worldName);

    bool coordValid = false;
    bool heightValid = false;

    if (isZeroBased) {
        coordValid = (x >= 0.0f && x <= worldSize && z >= 0.0f && z <= worldSize);
        heightValid = (y >= -50.0f && y <= 3000.0f);
    }
    else {
        float halfSize = worldSize * 0.5f;
        coordValid = (x >= -halfSize && x <= halfSize && z >= -halfSize && z <= halfSize);
        heightValid = (y >= -200.0f && y <= 3000.0f);
    }

    bool isValid = coordValid && heightValid;

    if (isValid) {
        float playerX = g_playerX.load();
        float playerY = g_playerY.load();
        float playerZ = g_playerZ.load();

        if (playerX != 0.0f || playerY != 0.0f || playerZ != 0.0f) {
            float distance = CalculateDistance(x, y, z, playerX, playerY, playerZ);

            if (distance > 500.0f) {
                isValid = false;
            }
        }
    }

    return isValid;
}
static bool TryReadEntityPosViaVisualState(HANDLE hp, uintptr_t ent, float out[3]) {
    if (!IsValidAddress(ent)) return false;

    uintptr_t vs = 0;
    if (!ReadPtr(hp, ent + OFFSET_WORLD_VISUALSTATE, vs) || !IsValidAddress(vs))
        return false;

    const uintptr_t possibleOffsets[] = {
           0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C,
           0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C,
           0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78, 0x7C,
           0x80, 0x84, 0x88, 0x8C, 0x90, 0x94, 0x98, 0x9C,
           0xA0, 0xA4, 0xA8, 0xAC, 0xB0, 0xB4, 0xB8, 0xBC
    };

    for (uintptr_t offset : possibleOffsets) {
        float rawPos[3];
        if (!Read3(hp, vs + offset, rawPos))
            continue;

        float x = rawPos[0], y = rawPos[1], z = rawPos[2];

        if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
        if (fabsf(x) > 1000000.0f || fabsf(y) > 1000000.0f || fabsf(z) > 1000000.0f) continue;
        if (fabsf(x) < 0.001f && fabsf(y) < 0.001f && fabsf(z) < 0.001f) continue;

        out[0] = x;
        out[1] = y;
        out[2] = z;

        if (IsValidPosition(x, y, z)) {
            return true;
        }
    }

    return false;
}
static std::vector<uintptr_t> ReadEntityPointers(uintptr_t arr, int maxSlots) {
    std::vector<uintptr_t> out;

    if (!IsValidAddress(arr)) {
        return out;
    }

    HANDLE self = GetCurrentProcess();
    int empty = 0;
    int valid = 0;

    for (int i = 0; i < maxSlots; i++) {
        uintptr_t ent = 0;
        uintptr_t slotAddr = arr + i * sizeof(uintptr_t);

        if (!ReadPtr(self, slotAddr, ent)) {
            if (i == 0 && valid == 0) {
                break;
            }
            break;
        }

        if (!IsValidAddress(ent)) {
            if (++empty > 100) {
                break;
            }
            continue;
        }

        out.push_back(ent);
        valid++;
    }

    return out;
}
static uintptr_t AutoDetectPosOffset(uintptr_t entityArray) {
    HANDLE self = GetCurrentProcess();
    auto ptrs = ReadEntityPointers(entityArray, EPS_AUTODETECT_SLOTS);

    if (ptrs.empty()) {
        return 0;
    }

    const uintptr_t candidates[] = {
        0x90,0x98,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x100,0x110,0x120,0x130,
        0x140,0x148,0x150,0x158,0x160,0x168,0x170,0x178,0x180,0x188,0x190,0x1A0
    };

    const size_t TEST_ENTITIES = 25;
    const int MIN_SUCCESS_RATE = 10;

    uintptr_t bestOff = 0;
    int bestCount = 0;
    int bestTested = 0;

    for (uintptr_t cand : candidates) {
        int good = 0;
        int tested = 0;

        for (size_t i = 0; i < (std::min)(ptrs.size(), TEST_ENTITIES); i++) {
            tested++;
            float v[3];
            if (TryReadVec3(self, ptrs[i], cand, v)) {
                if (IsLikelyCoord(v[0]) && IsLikelyCoord(v[1]) && IsLikelyCoord(v[2]) &&
                    !(fabsf(v[0]) < 1e-3f && fabsf(v[1]) < 1e-3f && fabsf(v[2]) < 1e-3f) &&
                    IsValidPosition(v[0], v[1], v[2])) {
                    good++;
                }
            }
        }

        if (good > bestCount) {
            bestCount = good;
            bestOff = cand;
            bestTested = tested;
        }
    }

    if (bestOff && bestCount >= MIN_SUCCESS_RATE) {
        return bestOff;
    }
    else if (bestOff) {
        return 0x188;
    }
    else {
        return 0x188;
    }
}
static std::vector<EPS::SimpleEntity> CollectNow(uintptr_t entityArray, uintptr_t posOff) {
    std::vector<EPS::SimpleEntity> out;

    if (!IsValidAddress(entityArray)) {
        return out;
    }

    HANDLE self = GetCurrentProcess();

    uintptr_t entityList = EPS::ReadEntityListFromWorld();
    if (entityList) {
        auto entityPointers = EPS::ReadEntitiesFromEntityList(entityList);

        float playerX = g_playerX.load();
        float playerY = g_playerY.load();
        float playerZ = g_playerZ.load();

        for (size_t i = 0; i < entityPointers.size(); i++) {
            uintptr_t ent = entityPointers[i];

            float pos[3] = { 0 };
            bool posValid = false;

            if (TryReadEntityPosViaVisualState(self, ent, pos)) {
                posValid = true;
            }
            else if (posOff && TryReadVec3(self, ent, posOff, pos)) {
                posValid = true;
            }

            if (posValid) {
                float distance = CalculateDistance(playerX, playerY, playerZ, pos[0], pos[1], pos[2]);

                // РАЗНЫЕ ДИСТАНЦИИ ДЛЯ РАЗНЫХ ТИПОВ ОБЪЕКТОВ
                auto entityInfo = EntityClassifier::ClassifyEntityByPosition(
                    ent, pos[0], pos[1], pos[2], playerX, playerY, playerZ);

                bool isLiving = EntityClassifier::IsLivingEntity(entityInfo.type);
                bool isObstacle = entityInfo.isObstacle;

                // Живые цели: до 800м, Препятствия: до 500м
                float maxDistance = isLiving ? 500.0f : 500.0f;

                if (distance > maxDistance) {
                    continue;
                }

                // Игнорируем объекты слишком близко к игроку (это может быть сам игрок)
                if (distance < 20.0f) {
                    continue;
                }

                // СОБИРАЕМ ВСЕ: живые цели + препятствия
                if (isLiving || isObstacle) {
                    std::string entityName;
                    if (entityInfo.type == EntityClassifier::EntityType::PLAYER) {
                        entityName = "Player";
                    }
                    else if (entityInfo.type == EntityClassifier::EntityType::ZOMBIE) {
                        entityName = "Zombie";
                    }
                    else if (entityInfo.type == EntityClassifier::EntityType::ANIMAL) {
                        entityName = "Animal";
                    }
                    else {
                        // ВСЕ неизвестные объекты = препятствия
                        entityName = "Obstacle";
                    }

                    out.push_back(EPS::SimpleEntity{
                        (uint64_t)ent, pos[0], pos[1], pos[2],
                        isLiving, // isHuman для живых существ
                        entityName
                        });
                }
            }
        }
    }

    return out;
}
std::vector<EPS::SimpleEntity> EPS::CollectNowWithRecovery(uintptr_t entityArray, uintptr_t posOff) {
    std::vector<EPS::SimpleEntity> out;

    if (!IsValidAddress(entityArray)) {
        g_stabilityMonitor.ReportEntitySamplingFailure();
        return out;
    }

    static int consecutiveEmptyResults = 0;
    static int totalCycles = 0;
    static int totalEmptyCycles = 0;

    const int MAX_CONSECUTIVE_EMPTY = 10;
    const int CYCLES_BETWEEN_RECOVERY = 50;
    const int MAX_TOTAL_EMPTY_CYCLES = 500;

    totalCycles++;

    bool collectionSuccess = false;
    std::atomic<bool> threadFinished{ false };

    std::thread collectionThread([&]() {
        try {
            out = CollectNow(entityArray, posOff);
            collectionSuccess = true;
        }
        catch (...) {
        }
        threadFinished.store(true);
        });

    auto collectionStart = std::chrono::steady_clock::now();
    while (!threadFinished.load()) {
        if (std::chrono::steady_clock::now() - collectionStart > std::chrono::seconds(3)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (collectionThread.joinable()) {
        collectionThread.join();
    }

    if (!collectionSuccess) {
        g_stabilityMonitor.ReportEntitySamplingFailure();
        return out;
    }

    std::vector<EPS::SimpleEntity> filteredOut;
    float playerX = g_playerX.load();
    float playerY = g_playerY.load();
    float playerZ = g_playerZ.load();

    for (const auto& entity : out) {
        float distance = CalculateDistance(playerX, playerY, playerZ, entity.x, entity.y, entity.z);
        if (distance > 3.0f) {
            filteredOut.push_back(entity);
        }
    }
    out = filteredOut;

    if (!out.empty()) {
        consecutiveEmptyResults = 0;
        totalEmptyCycles = 0;
        g_stabilityMonitor.ReportEntitySamplingSuccess();

        if (totalCycles % 1000 == 0 && posOff == 0) {
            uintptr_t newOffset = AutoDetectPosOffset(entityArray);
            if (newOffset) {
                g_posOffset.store(newOffset);
            }
        }
    }
    else {
        consecutiveEmptyResults++;
        totalEmptyCycles++;
        g_stabilityMonitor.ReportEntitySamplingFailure();

        bool shouldRecover = false;
        std::string recoveryReason;

        if (totalEmptyCycles >= MAX_TOTAL_EMPTY_CYCLES) {
            shouldRecover = true;
            recoveryReason = "CRITICAL: Too many total empty cycles";
        }
        else if (consecutiveEmptyResults >= MAX_CONSECUTIVE_EMPTY &&
            totalCycles % CYCLES_BETWEEN_RECOVERY == 0) {
            shouldRecover = true;
            recoveryReason = "Consecutive empty results threshold";
        }
        else if (g_stabilityMonitor.ShouldAttemptRecovery()) {
            shouldRecover = true;
            recoveryReason = "Stability monitor recommendation";
        }

        if (shouldRecover) {
            EPS::PerformEntitySamplingRecovery(entityArray);
            g_stabilityMonitor.RecordRecoveryAttempt();

            consecutiveEmptyResults = MAX_CONSECUTIVE_EMPTY / 2;
            totalEmptyCycles = MAX_TOTAL_EMPTY_CYCLES / 2;
        }
    }

    return out;
}
void EPS::PerformEntitySamplingRecovery(uintptr_t entityArray) {
    uintptr_t newOffset = AutoDetectPosOffset(entityArray);
    if (newOffset) {
        g_posOffset.store(newOffset);
    }

    std::lock_guard<std::mutex> lock(g_snapshotMutex);
    g_lastSnapshot.clear();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
uintptr_t EPS::GetWorldPtr() {
    static uintptr_t worldPtr = 0;
    if (worldPtr == 0) {
        // Получаем базовый адрес модуля и добавляем смещение
        HMODULE hModule = GetModuleHandle(NULL); // или конкретный модуль
        if (hModule) {
            worldPtr = (uintptr_t)hModule + OFFSET_WORLD_STATIC;
        }
    }
    return worldPtr;
}
uintptr_t EPS::ReadEntityListFromWorld() {
    uintptr_t worldPtr = GetWorldPtr();
    if (!worldPtr) {
        return 0;
    }

    uintptr_t world = 0;
    if (!ReadPtr(GetCurrentProcess(), worldPtr, world) || !world) {
        return 0;
    }

    uintptr_t entityList = 0;
    if (!ReadPtr(GetCurrentProcess(), world + OFFSET_WORLD_ENTITYARRAY, entityList) || !entityList) {
        return 0;
    }

    return entityList;
}
std::string GetSimpleEntityType(uintptr_t entityPtr) {
    uintptr_t humanType = 0;
    if (SafeReadPtr(entityPtr + OFFSET_HUMAN_HUMANTYPE, humanType) && humanType) {
        return "Living";
    }
    return "Object";
}
std::vector<uintptr_t> EPS::ReadEntitiesFromEntityList(uintptr_t entityList) {
    std::vector<uintptr_t> entities;

    if (!entityList) {
        return entities;
    }

    int validEntities = 0;
    const int MAX_SLOTS_TO_SCAN = 1000;

    for (int i = 0; i < MAX_SLOTS_TO_SCAN; i++) {
        uintptr_t entityPtr = 0;
        uintptr_t entityAddress = entityList + (i * sizeof(uintptr_t));

        if (ReadPtr(GetCurrentProcess(), entityAddress, entityPtr) && entityPtr && IsValidAddress(entityPtr)) {
            entities.push_back(entityPtr);
            validEntities++;

            if (validEntities > 2) {
                break;
            }
        }
        else {
            if (i > 50 && validEntities == 0) {
                break;
            }
        }
    }

    return entities;
}
std::vector<uintptr_t> ReadEntitiesAlternative(uintptr_t world) {
    std::vector<uintptr_t> entities;

    std::vector<uintptr_t> nearEntities, farEntities;

    uintptr_t nearEntList = 0;
    if (ReadPtr(GetCurrentProcess(), world + OFFSET_WORLD_ENTITYARRAY, nearEntList) && nearEntList) {
        nearEntities = EPS::ReadEntitiesFromEntityList(nearEntList);
        entities.insert(entities.end(), nearEntities.begin(), nearEntities.end());
    }

    uintptr_t farEntList = 0;
    if (ReadPtr(GetCurrentProcess(), world + OFFSET_WORLD_FARENTLIST, farEntList) && farEntList) {
        farEntities = EPS::ReadEntitiesFromEntityList(farEntList);
        entities.insert(entities.end(), farEntities.begin(), farEntities.end());
    }

    uintptr_t slowEntList = 0;
    if (ReadPtr(GetCurrentProcess(), world + OFFSET_WORLD_SLOWENTLIST, slowEntList) && slowEntList) {
        int slowEntValidCount = 0;
        if (Read32(GetCurrentProcess(), world + OFFSET_WORLD_SLOWENTVALIDCOUNT, &slowEntValidCount, sizeof(slowEntValidCount))) {
            std::vector<uintptr_t> slowEntities;
            for (int i = 0; i < std::min(slowEntValidCount, 500); i++) {
                uintptr_t entityPtr = 0;
                uintptr_t entityAddress = slowEntList + (i * sizeof(uintptr_t));

                if (ReadPtr(GetCurrentProcess(), entityAddress, entityPtr) && entityPtr && IsValidAddress(entityPtr)) {
                    slowEntities.push_back(entityPtr);
                }
            }

            entities.insert(entities.end(), slowEntities.begin(), slowEntities.end());
        }
    }

    std::sort(entities.begin(), entities.end());
    entities.erase(std::unique(entities.begin(), entities.end()), entities.end());

    return entities;
}
std::vector<EPS::SimpleEntity> EPS::CollectNowWithEntityList() {
    std::vector<EPS::SimpleEntity> out;

    uintptr_t worldPtr = GetWorldPtr();
    if (!worldPtr) {
        return out;
    }

    uintptr_t world = 0;
    if (!ReadPtr(GetCurrentProcess(), worldPtr, world) || !world) {
        return out;
    }

    std::vector<uintptr_t> entityPointers;
    entityPointers = ReadEntitiesAlternative(world);

    if (entityPointers.empty()) {
        uintptr_t entityList = ReadEntityListFromWorld();
        if (entityList) {
            entityPointers = ReadEntitiesFromEntityList(entityList);
        }
    }

    if (entityPointers.empty()) {
        return out;
    }

    HANDLE self = GetCurrentProcess();
    float playerX = g_playerX.load();
    float playerY = g_playerY.load();
    float playerZ = g_playerZ.load();

    for (size_t i = 0; i < entityPointers.size(); i++) {
        uintptr_t ent = entityPointers[i];

        float pos[3] = { 0 };
        bool posValid = false;

        if (TryReadEntityPosViaVisualState(self, ent, pos)) {
            posValid = true;
        }
        else if (g_posOffset.load() && TryReadVec3(self, ent, g_posOffset.load(), pos)) {
            posValid = true;
        }

        if (posValid && IsValidPosition(pos[0], pos[1], pos[2])) {
            auto entityInfo = EntityClassifier::ClassifyEntityByPosition(
                ent, pos[0], pos[1], pos[2], playerX, playerY, playerZ);

            float distance = CalculateDistance(playerX, playerY, playerZ, pos[0], pos[1], pos[2]);

            if (distance > 20.0f && distance < 500.0f) {
                std::string entityName;
                if (entityInfo.type == EntityClassifier::EntityType::PLAYER) {
                    entityName = "Player";
                }
                else if (entityInfo.type == EntityClassifier::EntityType::ZOMBIE) {
                    entityName = "Zombie";
                }
                else if (entityInfo.type == EntityClassifier::EntityType::ANIMAL) {
                    entityName = "Animal";
                }
                else {
                    entityName = "Object"; // ВСЕ неизвестные объекты
                }

                out.push_back(EPS::SimpleEntity{
                    (uint64_t)ent,
                    pos[0], pos[1], pos[2],
                    EntityClassifier::IsLivingEntity(entityInfo.type),
                    entityName
                    });
            }
        }
    }

    return out;
}
static DWORD WINAPI EPS_ThreadMain_NoSEH(LPVOID) {
    static int totalRestarts = 0;
    const int MAX_RESTARTS = 3; 
    const auto RESTART_DELAY = std::chrono::seconds(5); 

    auto lastRestartTime = std::chrono::steady_clock::now();

    while (g_epsRun.load()) {
        try {
            uintptr_t currentArray = g_epsEntityArray.load();

            if (!IsValidAddress(currentArray)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            std::vector<EPS::SimpleEntity> ents;
            bool collectionSuccess = false;
            std::atomic<bool> threadFinished{ false };

            std::thread collectionThread([&]() {
                try {
                    ents = EPS::CollectNowWithRecovery(currentArray, g_posOffset.load());
                    collectionSuccess = true;
                }
                catch (...) {
                }
                threadFinished.store(true);
                });

            auto collectionStart = std::chrono::steady_clock::now();
            while (!threadFinished.load()) {
                if (std::chrono::steady_clock::now() - collectionStart > std::chrono::seconds(3)) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (collectionThread.joinable()) {
                collectionThread.join();
            }

            if (!collectionSuccess) {
                auto now = std::chrono::steady_clock::now();
                if (totalRestarts < MAX_RESTARTS &&
                    (now - lastRestartTime) > RESTART_DELAY) {

                    totalRestarts++;
                    lastRestartTime = now;

                    if (totalRestarts == 1) {
                        EPS::CleanupMemory(false);
                    }
                    else if (totalRestarts == 2) {
                        uintptr_t newOffset = AutoDetectPosOffset(currentArray);
                        if (newOffset) {
                            g_posOffset.store(newOffset);
                        }
                    }
                    else if (totalRestarts >= MAX_RESTARTS) {
                        Log("[LOGEN] EPS: Critical failure, cleaning data only");
                        EPS::CleanupMemory(false);
                        totalRestarts = MAX_RESTARTS - 1;
                    }
                    continue;
                }
            }
            else {
                if (totalRestarts > 0) {
                    totalRestarts = 0;
                }

                {
                    std::lock_guard<std::mutex> lock(g_snapshotMutex);
                    g_lastSnapshot = ents;
                }
            }

            Sleep(EPS_POLL_MS);
        }
        catch (...) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    return 0;
}
static DWORD WINAPI EPS_ThreadMain(LPVOID param) {
    return EPS_ThreadMain_NoSEH(param);
}
void TestEntityListContents(uintptr_t entityList, const std::string& listName) {
    const int MAX_TEST_ENTITIES = 10;
    int validEntities = 0;

    for (int i = 0; i < MAX_TEST_ENTITIES; i++) {
        uintptr_t entityPtr = 0;
        uintptr_t entityAddress = entityList + (i * sizeof(uintptr_t));

        if (ReadPtr(GetCurrentProcess(), entityAddress, entityPtr) && entityPtr && IsValidAddress(entityPtr)) {
            validEntities++;

            std::string className = EntityClassifier::TryReadClassName(entityPtr);

            float pos[3] = { 0 };
            if (TryReadEntityPosViaVisualState(GetCurrentProcess(), entityPtr, pos)) {
            }

            if (validEntities >= 3) break;
        }
    }
}
std::vector<EPS::SimpleEntity> EPS::GetLastSnapshot() {
    std::lock_guard<std::mutex> lock(g_snapshotMutex);
    return g_lastSnapshot;
}
bool EPS::Start(uintptr_t entityArrayAddr) {
    if (!IsValidAddress(entityArrayAddr)) {
        return false;
    }

    if (g_epsRun.exchange(true)) {
        return true;
    }

    g_epsEntityArray.store(entityArrayAddr);

    g_epsThread = CreateThread(nullptr, 0, EPS_ThreadMain, nullptr, 0, nullptr);

    if (!g_epsThread) {
        g_epsRun.store(false);
        return false;
    }

    return true;
}
void EPS::Stop() {
    if (!g_epsRun.exchange(false)) return;
    if (g_epsThread) {
        WaitForSingleObject(g_epsThread, 3000);
        CloseHandle(g_epsThread);
        g_epsThread = nullptr;
    }

    std::lock_guard<std::mutex> lock(g_snapshotMutex);
    g_lastSnapshot.clear();
}
bool EPS::IsRunning() {
    return g_epsRun.load();
}
std::vector<EPS::SimpleEntity> EPS::Snapshot(uintptr_t entityArrayAddr) {
    return CollectNowWithEntityList();
}
uintptr_t EPS::GetPosOffset() {
    return g_posOffset.load();
}
void EPS::SetPosOffset(uintptr_t off) {
    g_posOffset.store(off);
}
void EPS::EPS_SetWorldSize(float ws) {
    g_worldSize.store(ws);
    g_worldSizeLocked.store(true);
}
float EPS::EPS_GetWorldSize() {
    return g_worldSize.load();
}
std::string EPS::EPS_GetWorldName() {
    std::lock_guard<std::mutex> lock(g_worldNameMutex);
    return g_worldName;
}
void EPS::EPS_SetWorldName(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_worldNameMutex);
    g_worldName = name;
}
float EPS::EPS_ComputeAngleDeg(const float camPos[3], const float camFwd[3], float tx, float ty, float tz) {
    const float dx = tx - camPos[0];
    const float dy = ty - camPos[1];
    const float dz = tz - camPos[2];

    float f0 = camFwd[0], f1 = camFwd[1], f2 = camFwd[2];
    const float fn = std::sqrt(f0 * f0 + f1 * f1 + f2 * f2);
    if (fn > 1e-6f) { f0 /= fn; f1 /= fn; f2 /= fn; }

    const float dn = std::sqrt(dx * dx + dy * dy + dz * dz);
    if (dn < 1e-6f) return 0.0f;

    float cosang = (dx * f0 + dy * f1 + dz * f2) / dn;
    cosang = Clamp01(cosang);
    return std::acos(cosang) * 57.2957795f;
}
void EPS::EPS_BuildLOSBucket(const std::vector<SimpleEntity>& snapshot, const float camPos[3], const float camFwd[3], std::vector<TargetLOS>& out, int limit) {
    out.clear();
    out.reserve(32);

    for (const auto& s : snapshot) {
        TargetLOS t{};
        t.id = s.id;
        t.pos[0] = s.x; t.pos[1] = s.y; t.pos[2] = s.z;
        t.name = s.name.empty() ? "Unnamed" : s.name.c_str();
        t.targetName = s.name.empty() ? "Entity" : s.name;

        // Классификация сущности
        auto entityInfo = EntityClassifier::ClassifyEntityByPosition((uintptr_t)s.id, s.x, s.y, s.z, camPos[0], camPos[1], camPos[2]);
        t.entityClass = entityInfo.className;
        t.entityType = EntityClassifier::EntityTypeToString(entityInfo.type);
        t.isDangerous = entityInfo.isHostile;
        t.isLiving = EntityClassifier::IsLivingEntity(entityInfo.type);

        // Вычисление дистанции и угла
        const float dx = s.x - camPos[0];
        const float dy = s.y - camPos[1];
        const float dz = s.z - camPos[2];
        t.dist = std::sqrt(dx * dx + dy * dy + dz * dz);
        t.angDeg = EPS_ComputeAngleDeg(camPos, camFwd, s.x, s.y, s.z);
        out.push_back(t);
    }

    // Сортировка остается
    std::sort(out.begin(), out.end(),
        [](const TargetLOS& a, const TargetLOS& b) {
            if (a.angDeg != b.angDeg) return a.angDeg < b.angDeg;
            return a.dist < b.dist;
        });

    if (limit > 0 && (int)out.size() > limit) {
        out.resize(limit);
    }
}
void EPS::UpdateESPDataFromEntities() {
    auto snapshot = GetLastSnapshot();
    if (snapshot.empty()) {
        return;
    }

    float playerX = g_playerX.load();
    float playerY = g_playerY.load();
    float playerZ = g_playerZ.load();

    int entityCount = 0;
    for (const auto& entity : snapshot) {
        float distance = CalculateDistance(playerX, playerY, playerZ, entity.x, entity.y, entity.z);
        entityCount++;
    }
}
void EPS::RunDiagnostics(uintptr_t entityArrayAddr) {

    auto snapshot = Snapshot(entityArrayAddr);

    if (!snapshot.empty()) {
        for (size_t i = 0; i < std::min(snapshot.size(), size_t(5)); i++) {
            const auto& entity = snapshot[i];
        }
    }
}
EPS::DebugInfo EPS::GetDebugInfo() {
    std::lock_guard<std::mutex> lock(g_snapshotMutex);
    DebugInfo info{};
    info.totalEntities = g_lastSnapshot.size();
    info.humanEntities = std::count_if(g_lastSnapshot.begin(), g_lastSnapshot.end(),
        [](const SimpleEntity& e) { return e.isHuman; });
    info.validPositions = info.totalEntities;
    info.worldSize = g_worldSize.load();
    info.worldName = g_worldName;
    return info;
}
struct WorldSizeKV { const char* key; float size; };
static const WorldSizeKV kWorldSizes[] = {
    {"chernarus",     15360.0f},
    {"deerisle",      16380.0f},
    {"livonia",       12800.0f},
    {"enoch",         12800.0f},
    {"namalsk",       12800.0f},
    {"rostow",        14336.0f},
    {"esseker",       12800.0f},
    {"takistanplus",  12800.0f},
    {"banov",         15360.0f},
    {"chiemsee",      10240.0f},
    {"iztek",         8200.0f},
    {"melkart",       20477.0f},
    {"valning",       20477.0f},
    {"nukezzone",     15360.0f},
    {"pripyat",       20480.0f},
    {"vela",          10237.0f},
    {"yiprit",        20474.0f},
    {"nhchernobyl",   20480.0f},
    {"visisland",     20480.0f},
    {"alteria",       8200.0f},
    {"anastara",      10240.0f},
    {"arsteinen",     15360.0f},
    {"onforin",       24576.0f},
    {"ros",           20480.0f},
    {"sakhal",        15360.0f},
};
static const std::pair<const char*, const char*> kWorldAliases[] = {
    {"livonia",      "enoch"},
    {"livonia",      "enoch.wrp"},
    {"livonia",      "dz\\enoch\\world\\enoch.wrp"},
    {"enoch",        "livonia"},

    {"chernarus",    "chernarusplus"},
    {"chernarus",    "chernarus_plus"},
    {"chernarus",    "chernarusplus.wrp"},
    {"chernarus",    "dz\\chernarusplus\\world\\chernarusplus.wrp"},

    {"takistanplus", "takistan"},
    {"takistanplus", "takistan_plus"},
    {"takistanplus", "takistanplus.wrp"},

    {"deerisle",     "deer_isle"},
    {"deerisle",     "deerisle.wrp"},

    {"visisland",    "vis_island"},
    {"visisland",    "visisland.wrp"},

    {"pripyat",      "pripyat"},
    {"pripyat",      "pripyat.wrp"},

    {"rostow",       "rostov"},
    {"rostow",       "rostow.wrp"},

    {"esseker",      "esseker.wrp"},
    {"namalsk",      "namalsk.wrp"},
    {"banov",        "banov.wrp"},
    {"chiemsee",     "chiem_see"},
    {"chiemsee",     "chiemsee.wrp"},
    {"iztek",        "iztek.wrp"},
    {"melkart",      "melkart.wrp"},
    {"valning",      "valning.wrp"},
    {"nukezzone",    "nukezone"},
    {"nukezzone",    "nukez_zone"},
    {"nukezzone",    "nukezzone.wrp"},
    {"yiprit",       "yprit"},
    {"yiprit",       "yiprit.wrp"},
    {"nhchernobyl",  "nh_chernobyl"},
    {"nhchernobyl",  "chernobyl"},
    {"nhchernobyl",  "nhchernobyl.wrp"},
    {"alteria",      "alteria.wrp"},
    {"anastara",     "anastara.wrp"},
    {"arsteinen",    "ar_steinen"},
    {"arsteinen",    "arsteinen.wrp"},
    {"onforin",      "onforin.wrp"},
    {"sakhal",       "sakhal.wrp"},
};
static inline bool is_word_char(unsigned char c) {
    return std::isalnum(c) || c == '_' || c == '-';
}
static float findWorldSizeCI(const std::string& name) {
    for (auto& kv : kWorldSizes) {
        std::string a = tolower_str(kv.key), b = tolower_str(name);
        if (a == b) return kv.size;
    }
    return 0.0f;
}
bool EPS::DetectWorldNameFromProcess() {
    if (g_worldSizeLocked.load()) {
        LogFormat("[LOGEN] [EPS] Detect: already locked worldSize=%.0f", g_worldSize.load());
        return true;
    }

    HMODULE hMain = GetModuleHandleW(nullptr);
    if (!hMain) { /*Log("[LOGEN] [EPS] Detect: GetModuleHandle(nullptr) failed");*/ return false; }

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hMain, &mi, sizeof(mi))) {
        /*Log("[LOGEN] [EPS] Detect: GetModuleInformation failed");*/ return false;
    }

    auto* base = static_cast<uint8_t*>(mi.lpBaseOfDll);
    size_t size = static_cast<size_t>(mi.SizeOfImage);
    LogFormat("[LOGEN] [EPS] Detect: scanning module base=0x%p size=0x%zX", base, size);

    struct SearchTok { std::string token; std::string label; float ws; bool isShort; };
    std::vector<SearchTok> tokens;
    tokens.reserve(sizeof(kWorldSizes) / sizeof(kWorldSizes[0]) + sizeof(kWorldAliases) / sizeof(kWorldAliases[0]));

    for (auto& kv : kWorldSizes) {
        tokens.push_back({ kv.key, kv.key, kv.size, std::strlen(kv.key) < 4 });
    }
    for (auto& al : kWorldAliases) {
        float ws = findWorldSizeCI(al.first);
        if (ws <= 0.0f) ws = findWorldSizeCI(al.second);
        if (ws > 0.0f) {
            std::string label = findWorldSizeCI(al.first) > 0.0f ? al.first : al.second;
            tokens.push_back({ al.second, label, ws, std::strlen(al.second) < 4 });
        }
    }

    struct Hit { std::string label; float ws; size_t off; std::string found; int score; };
    std::vector<Hit> hits;

    const size_t CHUNK = 1 << 20; // 1 MB
    std::string hay; hay.reserve(CHUNK + 256);

    for (size_t off = 0; off < size; off += CHUNK) {
        size_t take = std::min(CHUNK, size - off);
        hay.assign(reinterpret_cast<const char*>(base + off),
            reinterpret_cast<const char*>(base + off + take));
        std::string H = tolower_str(hay);

        for (const auto& tk : tokens) {
            const std::string key = tolower_str(tk.token);
            size_t pos = 0;
            while (true) {
                pos = H.find(key, pos);
                if (pos == std::string::npos) break;

                const bool allowChPlus =
                    (key == "chernarus" &&
                        (pos + key.size() + 4 <= H.size()) &&
                        H.compare(pos + key.size(), 4, "plus") == 0);

                if (pos > 0 && is_word_char(static_cast<unsigned char>(H[pos - 1]))) {
                    pos += key.size(); continue;
                }
                const size_t tail = pos + key.size();
                if (!allowChPlus && tail < H.size() && is_word_char(static_cast<unsigned char>(H[tail]))) {
                    pos += key.size(); continue;
                }

                size_t r = tail;
                if (allowChPlus) r = tail + 4;
                while (r < hay.size()) {
                    unsigned char c = static_cast<unsigned char>(hay[r]);
                    bool ok = std::isalnum(c) || c == '_' || c == '-' || c == '.' || c == '\\' || c == '/';
                    if (!ok) break;
                    ++r;
                }
                std::string found = hay.substr(pos, r - pos);
                std::string foundL = tolower_str(found);

                const bool hasWRP = (foundL.find(".wrp") != std::string::npos);
                const bool inWorld = (foundL.find("\\world\\") != std::string::npos) ||
                    (foundL.find("/world/") != std::string::npos);
                const bool pathSeg =
                    (foundL.find("/" + key + "/") != std::string::npos) ||
                    (foundL.find("\\" + key + "\\") != std::string::npos);

                if (tk.isShort && !(hasWRP || inWorld || pathSeg)) { pos += key.size(); continue; }

                int score = 100;
                if (hasWRP)  score += 200;
                if (inWorld) score += 140;
                if (pathSeg) score += 60;
                if (tolower_str(tk.label) == key) score += 30;
                if (key == "enoch" || key == "livonia") score += 50;
                if (foundL.find("plus") != std::string::npos &&
                    (key == "chernarus" || key == "chernarusplus")) score += 40;

                hits.push_back(Hit{ tk.label, tk.ws, off + pos, found, score });
                //LogFormat("[VEH] [EPS] HIT: foundText='%s' ~ key='%s' size=%.0f at +0x%zX (score=%d)",
                //    found.c_str(), tk.label.c_str(), tk.ws, off + pos, score);

                pos += key.size();
            }
        }
    }

    if (hits.empty()) {
        //Log("[VEH] [EPS] Detect: no matches");
        return false;
    }

    std::sort(hits.begin(), hits.end(),
        [](const Hit& a, const Hit& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.off < b.off;
        });

    const auto& pick = hits.front();
    g_worldSize.store(pick.ws);
    g_worldSizeLocked.store(true);
    EPS::EPS_SetWorldName(pick.label);
    LogFormat("[LOGEN] [EPS] WORLD SELECT: key='%s' -> worldSize=%.0f (at +0x%zX)",
        pick.label.c_str(), pick.ws, pick.off);
    return true;
}
bool EPS::EPS_SetWorldByName(const std::string& nameLike) {
    std::string lowerName = tolower_str(nameLike);

    for (auto& kv : kWorldSizes) {
        if (str_contains_ci(lowerName, kv.key)) {
            g_worldSize.store(kv.size);
            g_worldName = kv.key;
            g_worldSizeLocked.store(true);
            return true;
        }
    }

    return false;
}
static bool IsLivingEntityOrPart(const std::string& className) {
    if (className.empty() || className == "Unknown_Class") {
        return false; 
    }

    std::string lowerName = className;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // 1. ФИЛЬТР: Части тел (скелеты, кости)
    bool isBodyPart = (
        lowerName.find("spine") != std::string::npos ||
        lowerName.find("pelvis") != std::string::npos ||
        lowerName.find("leg") != std::string::npos ||
        lowerName.find("arm") != std::string::npos ||
        lowerName.find("shoulder") != std::string::npos ||
        lowerName.find("hand") != std::string::npos ||
        lowerName.find("head") != std::string::npos ||
        lowerName.find("foot") != std::string::npos ||
        lowerName.find("neck") != std::string::npos ||
        lowerName.find("chest") != std::string::npos ||
        lowerName.find("meat") != std::string::npos ||
        className == "Multiply" || // Мусор
        className.find("Zmb") == 0 
        );

    if (isBodyPart) return true;

    bool isLivingEntity = (
        lowerName.find("player") != std::string::npos ||
        lowerName.find("zombie") != std::string::npos ||
        lowerName.find("infected") != std::string::npos ||
        lowerName.find("animal") != std::string::npos ||
        lowerName.find("human") != std::string::npos ||
        lowerName.find("character") != std::string::npos ||
        lowerName.find("survivor") != std::string::npos ||
        lowerName.find("deer") != std::string::npos ||
        lowerName.find("cow") != std::string::npos ||
        lowerName.find("bear") != std::string::npos ||
        lowerName.find("wolf") != std::string::npos ||
        lowerName.find("boar") != std::string::npos
        );

    return isLivingEntity;
}
std::vector<uintptr_t> EPS::GetStaticObjects(uintptr_t world) {
    std::vector<uintptr_t> result;
    HANDLE self = GetCurrentProcess();

    float playerPos[3] = { g_playerX.load(), g_playerY.load(), g_playerZ.load() };

    //Log("[STATIC] SCANNING FOR STATIC OBJECTS ONLY (NO LIVING ENTITIES)");

    // 1. SlowEntityList (0x2010) - ОСНОВНОЙ источник статических объектов
    uintptr_t slowEntList = 0;
    if (ReadPtr(self, world + OFFSET_WORLD_SLOWENTLIST, slowEntList) && slowEntList) {
       // Log("[STATIC] Scanning SlowEntityList for static objects...");
        int slowCount = 0;
        if (Read32(self, world + OFFSET_WORLD_SLOWENTVALIDCOUNT, &slowCount, sizeof(slowCount))) {
            int scanLimit = std::min(slowCount, 20000);
            int found = 0;
            int filtered = 0;

            for (int i = 0; i < scanLimit; i++) {
                uintptr_t entity = 0;
                uintptr_t addr = slowEntList + (i * 8);

                if (ReadPtr(self, addr, entity) && entity && IsValidAddress(entity)) {
                    float pos[3] = { 0 };
                    if (TryReadEntityPosViaVisualState(self, entity, pos)) {
                        float dist = CalculateDistance(playerPos[0], playerPos[1], playerPos[2],
                            pos[0], pos[1], pos[2]);

                        if (dist < 500.0f && dist > 20.0f) {
                            std::string className = EntityClassifier::TryReadClassName(entity);

                            // ФИЛЬТРАЦИЯ: убираем живых существ и их части
                            if (!IsLivingEntityOrPart(className)) {
                                result.push_back(entity);
                                found++;

                                // Логируем первые 50 статических объектов
                                if (found <= 50) {
                                   // Log(("[STATIC] " + className + " at " + std::to_string((int)dist) + "m" + " pos [" + std::to_string((int)pos[0]) + ", " + std::to_string((int)pos[1]) + ", " + std::to_string((int)pos[2]) + "]").c_str());
                                }
                            }
                            else {
                                filtered++;
                            }
                        }
                    }
                }

                if (i % 2000 == 0 && i > 0) {
                   // Log(("[STATIC] SlowList progress: " + std::to_string(i) + "/" + std::to_string(scanLimit) + " found: " + std::to_string(found) + " filtered: " + std::to_string(filtered)).c_str());
                }
            }
           // Log(("[STATIC] SlowEntityList - Static objects: " + std::to_string(found) + ", Filtered living: " + std::to_string(filtered)).c_str());
        }
    }

    // 2. FarEntityList (0x1090) - дальние статические объекты
    uintptr_t farEntList = 0;
    if (ReadPtr(self, world + OFFSET_WORLD_FARENTLIST, farEntList) && farEntList) {
       // Log("[STATIC] Scanning FarEntityList for static objects...");
        int found = 0;
        int filtered = 0;

        for (int i = 0; i < 4000; i++) {
            uintptr_t entity = 0;
            uintptr_t addr = farEntList + (i * 8);

            if (ReadPtr(self, addr, entity) && entity && IsValidAddress(entity)) {
                float pos[3] = { 0 };
                if (TryReadEntityPosViaVisualState(self, entity, pos)) {
                    float dist = CalculateDistance(playerPos[0], playerPos[1], playerPos[2],
                        pos[0], pos[1], pos[2]);

                    if (dist < 500.0f && dist > 50.0f) {
                        std::string className = EntityClassifier::TryReadClassName(entity);

                        // ФИЛЬТРАЦИЯ: убираем живых существ и их части
                        if (!IsLivingEntityOrPart(className)) {
                            // Проверяем на дубликаты перед добавлением
                            if (std::find(result.begin(), result.end(), entity) == result.end()) {
                                result.push_back(entity);
                                found++;

                                // Логируем первые 30 статических объектов
                                if (found <= 30) {
                                   // Log(("[FARSTATIC] " + className + " at " + std::to_string((int)dist) + "m" + " pos [" + std::to_string((int)pos[0]) + ", " + std::to_string((int)pos[1]) + ", " + std::to_string((int)pos[2]) + "]").c_str());
                                }
                            }
                        }
                        else {
                            filtered++;
                        }
                    }
                }
            }
        }
       // Log(("[STATIC] FarEntityList - Static objects: " + std::to_string(found) + ", Filtered living: " + std::to_string(filtered)).c_str());
    }

    // 3. EntityList (0xF48) - БЛИЖНИЕ объекты 0-200м
    uintptr_t entityList = 0;
    if (ReadPtr(self, world + OFFSET_WORLD_ENTITYARRAY, entityList) && entityList) {
       // Log("[STATIC] Scanning EntityList for NEAR static objects...");
        int found = 0;
        int filtered = 0;

        for (int i = 0; i < 1000; i++) {
            uintptr_t entity = 0;
            uintptr_t addr = entityList + (i * 8);

            if (ReadPtr(self, addr, entity) && entity && IsValidAddress(entity)) {
                float pos[3] = { 0 };
                if (TryReadEntityPosViaVisualState(self, entity, pos)) {
                    float dist = CalculateDistance(playerPos[0], playerPos[1], playerPos[2],
                        pos[0], pos[1], pos[2]);

                    if (dist < 200.0f && dist > 2.0f) {
                        std::string className = EntityClassifier::TryReadClassName(entity);

                        // ФИЛЬТРАЦИЯ: убираем живых существ
                        if (!IsLivingEntityOrPart(className)) {
                            if (std::find(result.begin(), result.end(), entity) == result.end()) {
                                result.push_back(entity);
                                found++;
                            }
                        }
                        else {
                            filtered++;
                        }
                    }
                }
            }
        }
       // Log(("[STATIC] EntityList - Near static objects: " + std::to_string(found)).c_str());
    }

    // Убираем дубликаты
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());

    // Финальная статистика по типам
    std::map<std::string, int> buildingStats;

    for (uintptr_t entity : result) {
        std::string className = EntityClassifier::TryReadClassName(entity);
        buildingStats[className]++;
    }

    for (const auto& pair : buildingStats) {
       // Log(("[STATIC] " + pair.first + ": " + std::to_string(pair.second)).c_str());
    }
    Log(("[LOGEN] TOTAL STATIC OBJECTS: " + std::to_string(result.size())).c_str());
   // StartSightImg(("[VEH] ESP_LOOK_AT_INVISIBLE TEST TEST TEST SCORP " + std::to_string(result.size())).c_str());
   // Log("[STATIC] === FINAL STATIC OBJECTS STATISTICS ===");
    return result;
}

void EPS::CleanupMemory(bool fullReset)
{
    //Log("[LOGEN] EPS::CleanupMemory Start");

    if (fullReset) {
        {
            std::lock_guard<std::mutex> lock(g_snapshotMutex);
            g_lastSnapshot.clear();
            g_lastSnapshot.shrink_to_fit();
        }
        g_posOffset.store(0);
        uintptr_t currentArray = g_epsEntityArray.load();
        if (currentArray && IsValidAddress(currentArray)) {
            uintptr_t newOffset = AutoDetectPosOffset(currentArray);
            if (newOffset) {
                g_posOffset.store(newOffset);
            }
        }
    }
    else {
        std::lock_guard<std::mutex> lock(g_snapshotMutex);
        if (g_lastSnapshot.size() > 500) {
            g_lastSnapshot.erase(g_lastSnapshot.begin(),
                g_lastSnapshot.begin() + (g_lastSnapshot.size() - 500));
        }
        g_lastSnapshot.shrink_to_fit();
    }

    LogFormat("[LOGEN] EPS::CleanupMemory — End, snapshot size: %zu", g_lastSnapshot.size());
}