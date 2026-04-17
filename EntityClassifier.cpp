#include "EntityClassifier.h"
#include "LogUtils.h"
#include <algorithm>
#include <cmath>
#include <map>
#include <vector>
#include <Windows.h>

namespace EntityClassifier {
    static std::map<uintptr_t, std::vector<std::tuple<float, float, float>>> g_entityPositionHistory;
    static std::map<uintptr_t, uint64_t> g_entityLastUpdate;
    static uint64_t g_lastCleanupTime = 0;
    bool IsObstacleEntity(EntityType type) {
        return type == EntityType::UNKNOWN;
    }
    static bool SafeReadMemory(void* address, void* buffer, size_t size) {
        if (!address || !buffer) return false;
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(GetCurrentProcess(), address, buffer, size, &bytesRead) && bytesRead == size;
    }
    bool ReadPointer(uintptr_t address, uintptr_t& result) {
        return SafeReadMemory((void*)address, &result, sizeof(result));
    }
    static bool IsValidClassName(const std::string& className) {
        if (className.length() < 3 || className.length() > 128) {
            return false;
        }

        if (className.find(".anm") != std::string::npos ||
            className.find("DZ\\anims") != std::string::npos ||
            className.find("\\anm\\") != std::string::npos) {
            return false;
        }

        int printableCount = 0;
        int letterCount = 0;

        for (char c : className) {
            if (std::isprint((unsigned char)c)) {
                printableCount++;
            }
            if (std::isalpha((unsigned char)c)) {
                letterCount++;
            }
        }

        if (printableCount < className.length() * 0.8f) {
            return false;
        }

        if (letterCount < 2) {
            return false;
        }

        return true;
    }
    static EntityType ClassifyByClassName(const std::string& className) {
        if (className.empty() || className == "Unknown_Class") {
            return EntityType::UNKNOWN;
        }

        std::string lowerName = className;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        if (className.find("Zmb") == 0 || 
            lowerName.find("zombie") != std::string::npos ||
            lowerName.find("infected") != std::string::npos) {
            return EntityType::ZOMBIE;
        }

        // 2. Затем проверяем на игроков
        if (lowerName.find("player") != std::string::npos ||
            lowerName.find("survivor") != std::string::npos ||
            lowerName.find("character") != std::string::npos ||
            className.find("CPlayer") == 0 ||
            className.find("Player") == 0) {
            return EntityType::PLAYER;
        }

        // 3. Затем животные
        if (lowerName.find("animal") != std::string::npos ||
            lowerName.find("deer") != std::string::npos ||
            lowerName.find("cow") != std::string::npos ||
            lowerName.find("bear") != std::string::npos ||
            lowerName.find("wolf") != std::string::npos ||
            lowerName.find("boar") != std::string::npos) {
            return EntityType::ANIMAL;
        }

        return EntityType::UNKNOWN;
    }
    std::string TryReadClassName(uintptr_t entityPtr) {
        HANDLE self = GetCurrentProcess();

        uintptr_t humanType = 0;
        if (!ReadPointer(entityPtr + OFFSET_HUMAN_HUMANTYPE, humanType) || !humanType) {
            return "Unknown_Class";
        }

        const uintptr_t offsetsToTry[] = {
            0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98,
            0xA0, 0xA8, 0xB0
        };

        for (uintptr_t offset : offsetsToTry) {
            uintptr_t namePointer = 0;
            if (!ReadPointer(humanType + offset, namePointer) || !namePointer) {
                continue;
            }

            char buffer[256] = { 0 };
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(self, (LPCVOID)namePointer, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {

                for (size_t i = 0; i < bytesRead - 2; i++) {
                    if (std::isprint((unsigned char)buffer[i]) &&
                        std::isprint((unsigned char)buffer[i + 1])) {

                        std::string className;
                        size_t j = i;
                        int consecutivePrintable = 0;

                        while (j < bytesRead && j < i + 128) {
                            char c = buffer[j];
                            if (std::isprint((unsigned char)c)) {
                                className += c;
                                consecutivePrintable++;
                            }
                            else {
                                if (++consecutivePrintable > 3) break;
                                continue;
                            }
                            j++;
                        }

                        if (className.length() >= 4 && IsValidClassName(className)) {
                            int alphaCount = 0;
                            for (char c : className) {
                                if (std::isalpha((unsigned char)c)) alphaCount++;
                            }

                            if (alphaCount >= 2) {
                                return className;
                            }
                        }
                    }
                }
            }
        }

        return "Unknown_Class";
    }
    EntityInfo ClassifyEntityByPosition(uintptr_t entityPtr, float x, float y, float z, float playerX, float playerY, float playerZ) {
        EntityInfo info{};
        info.type = EntityType::UNKNOWN;
        info.className = "Unknown";
        info.isHostile = false;
        info.isInteractive = false;

        info.isObstacle = true; 
        info.obstacleHeight = y;

        std::string className = TryReadClassName(entityPtr);
        info.className = className;

        EntityType classBasedType = ClassifyByClassName(className);
        if (classBasedType != EntityType::UNKNOWN) {
            info.type = classBasedType;
            info.isObstacle = false;

            if (info.type == EntityType::PLAYER) {
                info.isHostile = true;
                info.isInteractive = true;
            }
            else if (info.type == EntityType::ZOMBIE) {
                info.isHostile = true;
                info.isInteractive = true;
            }
            else if (info.type == EntityType::ANIMAL) {
                info.isHostile = false;
                info.isInteractive = true;
            }
        }
        uint64_t currentTime = GetTickCount64();
        if (currentTime - g_lastCleanupTime > 30000) {
            for (auto it = g_entityPositionHistory.begin(); it != g_entityPositionHistory.end();) {
                if (currentTime - g_entityLastUpdate[it->first] > 60000) {
                    g_entityLastUpdate.erase(it->first);
                    it = g_entityPositionHistory.erase(it);
                }
                else {
                    ++it;
                }
            }
            g_lastCleanupTime = currentTime;
        }

        return info;
    }
    std::string EntityTypeToString(EntityType type) {
        switch (type) {
        case EntityType::PLAYER: return "Player";
        case EntityType::ZOMBIE: return "Zombie";
        case EntityType::ANIMAL: return "Animal";
        case EntityType::UNKNOWN: return "Obstacle"; 
        default: return "Unknown";
        }
    }
    bool IsDangerousEntity(EntityType type) {
        return type == EntityType::PLAYER || type == EntityType::ZOMBIE;
    }
    bool IsLivingEntity(EntityType type) {
        return type == EntityType::PLAYER || type == EntityType::ZOMBIE || type == EntityType::ANIMAL;
    }
    bool Initialize() {
        return true;
    }
    void PrintClassificationStats() {
    }
}