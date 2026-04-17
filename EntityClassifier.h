#pragma once
#include <string>
#include <unordered_map>

namespace EntityClassifier {

    enum class EntityType {
        UNKNOWN,    // Все объекты, которые не можем точно определить
        PLAYER,     // Только игроки
        ZOMBIE,     // Только зомби  
        ANIMAL      // Только животные
    };

    struct EntityInfo {
        EntityType type;
        std::string className;
        bool isHostile;
        bool isInteractive;
        bool isObstacle;
        float obstacleHeight;
    };

    // Основные функции
    EntityInfo ClassifyEntityByPosition(uintptr_t entityPtr, float x, float y, float z,
        float playerX, float playerY, float playerZ);

    std::string EntityTypeToString(EntityType type);
    bool IsDangerousEntity(EntityType type);
    bool IsLivingEntity(EntityType type);
    bool IsObstacleEntity(EntityType type);
    bool Initialize();
    void PrintClassificationStats();

    // Функции чтения данных
    std::string TryReadClassName(uintptr_t entityPtr);
    bool ReadPointer(uintptr_t address, uintptr_t& result);
}