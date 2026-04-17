#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <Windows.h>

namespace EPS {

    struct SimpleEntity {
        uint64_t    id;
        float       x, y, z;
        bool        isHuman;
        std::string name;
    };

    // Основные функции
    std::vector<SimpleEntity> GetLastSnapshot();
    void UpdateESPDataFromEntities();
    void RunDiagnostics(uintptr_t entityArrayAddr);

    // Статистика
    struct DebugInfo {
        size_t totalEntities;
        size_t humanEntities;
        size_t validPositions;
        float worldSize;
        std::string worldName;
    };
    DebugInfo GetDebugInfo();

    // Управление
    bool Start(uintptr_t entityArrayAddr);
    void Stop();
    bool IsRunning();
    std::vector<SimpleEntity> Snapshot(uintptr_t entityArrayAddr);

    // Настройки
    uintptr_t GetPosOffset();
    void      SetPosOffset(uintptr_t off);

    // Мир
    bool  DetectWorldNameFromProcess();
    float EPS_GetWorldSize();
    void  EPS_SetWorldSize(float ws);
    bool  EPS_SetWorldByName(const std::string& nameLike);

    // LOS система
    struct TargetLOS {
        uint64_t    id;
        float       pos[3];
        const char* name;
        float       dist;
        float       angDeg;

        // Классификация
        std::string targetName;
        std::string entityClass;
        std::string entityType;
        bool        isDangerous;
        bool        isLiving;
    };

    float EPS_ComputeAngleDeg(const float camPos[3], const float camFwd[3],
        float tx, float ty, float tz);

    void EPS_BuildLOSBucket(const std::vector<SimpleEntity>& snapshot, const float camPos[3], const float camFwd[3], std::vector<TargetLOS>& out, int limit = 16);

    uintptr_t ReadEntityListFromWorld();
    std::vector<SimpleEntity> CollectNowWithEntityList();
    std::string EPS_GetWorldName();
    void EPS_SetWorldName(const std::string& name);

    // Восстановление и утилиты
    void PerformEntitySamplingRecovery(uintptr_t entityArray);
    std::vector<SimpleEntity> CollectNowWithRecovery(uintptr_t entityArray, uintptr_t posOff);

    // Вспомогательные функции
    uintptr_t GetWorldPtr();
    std::vector<uintptr_t> ReadEntitiesFromEntityList(uintptr_t entityList);
    std::vector<uintptr_t> GetStaticObjects(uintptr_t world);

    void CleanupMemory(bool fullReset);
}