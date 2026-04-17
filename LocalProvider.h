#pragma once
#include <cstdint>
#include "BehaviorDetector.h"  // BDLocalSnapshot
#include <unordered_map>

static std::unordered_map<std::string, std::string> CreateMapConfig() {
    std::unordered_map<std::string, std::string> config;

    config["alteria"] = "zero";
    config["iztek"] = "zero";
    config["chiemsee"] = "zero";
    config["anastara"] = "zero";
    config["banov"] = "zero";
    config["enoch"] = "zero";
    config["livonia"] = "zero";
    config["chernarus"] = "zero";
    config["chernarusplus"] = "zero";
    config["deerisle"] = "zero";
    config["namalsk"] = "zero";
    config["rostow"] = "zero";
    config["esseker"] = "zero";
    config["takistanplus"] = "zero";
    config["takistan"] = "zero";
    config["melkart"] = "zero";
    config["valning"] = "zero";
    config["nukezzone"] = "zero";
    config["pripyat"] = "zero";
    config["vela"] = "zero";
    config["yiprit"] = "zero";
    config["nhchernobyl"] = "zero";
    config["visisland"] = "zero";
    config["arsteinen"] = "zero";
    config["onforin"] = "zero";
    config["ros"] = "zero";
    config["sakhal"] = "zero";

    return config;
}

// Новая функция для определения системы координат
bool LP_IsZeroBasedMap(const std::string& worldName);

// Передать адрес World (нужен для цепочек чтения)
void LP_SetWorld(uintptr_t world);
void LP_ValidateWorldPointer(uintptr_t expectedWorld);

// Снимок локальной телеметрии (камера/углы/факт выстрела и т.п.)
bool GetLocalSnapshot(BDLocalSnapshot& out);

// Прямой доступ к камере (позиция + нормализованный forward) — нужен для ESP-эвристики
bool LP_GetCamera(float outPos[3], float outFwd[3]);
bool LP_GetCameraWithRetry(float outPos[3], float outFwd[3], int maxRetries = 3);