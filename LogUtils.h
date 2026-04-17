#pragma once
#include <cstdint>
#include <string>
#include <atomic>
#include <chrono>  // Добавьте эту строку
#include <vector>  // Добавьте для vector
#include <mutex>   // Добавьте для mutex
#include <unordered_map>
/* ==== World / Modbase ==== */
constexpr uintptr_t OFFSET_WORLD_STATIC = 0xF4B050;   // Modbase.World
constexpr uintptr_t OFFSET_WORLD_VISUALSTATE = 0x1C8;      // Human.VisualState
constexpr uintptr_t OFFSET_WORLD_SLOWENTVALIDCOUNT = 0x1F90;     // World.SlowEntValidCount
constexpr uintptr_t OFFSET_WORLD_SLOWENTLIST = 0x2010;     // World.SlowEntList
constexpr uintptr_t OFFSET_WORLD_ENTITYARRAY = 0xF48;      // World.NearEntList
constexpr uintptr_t OFFSET_WORLD_CAMERA = 0x1B8;      // World.Camera
constexpr uintptr_t OFFSET_WORLD_BULLETLIST = 0xE00;      // World.BulletList
constexpr uintptr_t OFFSET_WORLD_FARENTLIST = 0x1090;     // World.FarEntList
constexpr uintptr_t OFFSET_LOCALPLAYER_PTR = 0x2960;     // World.LocalPlayer
constexpr uintptr_t OFFSET_PLAYER_ITEMINHANDS = 0x6E0;      // DayZPlayer.ItemInHands (оставил как у тебя)
constexpr uintptr_t OFFSET_DAYZPLAYER_SKELETON = 0x7E8;      // DayZPlayer.Skeleton
constexpr uintptr_t OFFSET_HUMAN_HUMANTYPE = 0x180;      // Human.HumanType
constexpr uintptr_t OFFSET_CAMERA_INV_FWD = 0x20;       // Camera.InvertedViewForward
constexpr uintptr_t OFFSET_CAMERA_INV_TRANSL = 0x2C;       // Camera.InvertedViewTranslation
constexpr uintptr_t OFFSET_SKELETON_ANIMCLASS1 = 0x98;       // Skeleton.AnimClass1
constexpr uintptr_t OFFSET_WEAPON_INFOTABLE = 0x6B8;      // Weapon.WeaponInfoTable
constexpr uintptr_t OFFSET_MAG_AMMOCOUNT = 0x6B4;      // Magazine.AmmoCount
constexpr uintptr_t OFFSET_WEAPONINV_MAGREF = 0x150;      // WeaponInventory.MagazineRef
/*
constexpr uintptr_t OFFSET_WORLD_SLOWENTSIZE = 0x8;        // World.SlowEntSize (внутри slow-листа)
constexpr uintptr_t OFFSET_WORLD_NOGRASS = 0xC00;      // World.NoGrass
constexpr uintptr_t OFFSET_WORLD_LOCALOFFSET = 0x95E772;   // World.LocalOffset (заменил твоё старое)
*/

/* ==== LocalPlayer / Human ==== */
/*
constexpr uintptr_t OFFSET_HUMAN_INVENTORY = 0x658;      // Human.Inventory / DayZPlayer.Inventory
constexpr uintptr_t OFFSET_HUMAN_LODSHAPE = 0x208;      // Human.LodShape
constexpr uintptr_t OFFSET_PLAYER_NETWORKID = 0x6E4;      // DayZPlayer.NetworkID
constexpr uintptr_t OFFSET_DAYZPLAYER_ISDEAD = 0xE2;       // DayZPlayer.isDead (byte)
constexpr uintptr_t OFFSET_DAYZPLAYER_NETWORKCLIENT = 0x50;       // DayZPlayer.NetworkClientPtr
*/

/* ==== VisualState ==== */
/*
constexpr uintptr_t OFFSET_VISSTATE_TRANSFORM = 0x8;        // VisualState.Transform
constexpr uintptr_t OFFSET_VISSTATE_INVTRANSFORM = 0xA4;       // VisualState.InverseTransform
*/

/* ==== Inventory / Cargo ==== */
/*
constexpr uintptr_t OFFSET_ITEMINV_CARGOGRID = 0x148;      // ItemInventory.CargoGrid
constexpr uintptr_t OFFSET_CARGOGRID_ITEMLIST = 0x38;       // CargoGrid.ItemList
constexpr uintptr_t OFFSET_ITEMINV_QUALITY = 0x194;      // ItemInventory.Quality
constexpr uintptr_t OFFSET_DZPINV_HANDS = 0xF8;       // DayZPlayerInventory.Hands
constexpr uintptr_t OFFSET_DZPINV_CLOTHING = 0x150;      // DayZPlayerInventory.Clothing
constexpr uintptr_t OFFSET_DZPINV_HANDITEMVALID = 0x1B0;      // DayZPlayerInventory.HandItemValid
*/

/* ==== HumanType ==== */
/*
constexpr uintptr_t OFFSET_HUMANTYPE_OBJECTNAME = 0x70;       // HumanType.ObjectName
constexpr uintptr_t OFFSET_HUMANTYPE_CATEGORYNAME = 0xA8;       // HumanType.CategoryName
*/

/* ==== Names ==== */
/*
constexpr uintptr_t OFFSET_SCOREBOARD_NAME = 0xF8;       // ScoreboardIdentity.Name
constexpr uintptr_t OFFSET_SCOREBOARD_STEAMID = 0xA0;       // ScoreboardIdentity.SteamID
constexpr uintptr_t OFFSET_SCOREBOARD_NETID = 0x30;       // ScoreboardIdentity.NetworkID
*/

/* ==== Camera ==== */
/*
constexpr uintptr_t OFFSET_CAMERA_VIEW = 0x8;        // Camera.ViewMatrix
constexpr uintptr_t OFFSET_CAMERA_VIEWPORTMATRIX = 0x58;       // Camera.ViewPortMatrix
constexpr uintptr_t OFFSET_CAMERA_INV_UP = 0x14;       // Camera.InvertedViewUp
constexpr uintptr_t OFFSET_CAMERA_VIEWPROJ = 0xD0;       // Camera.ViewProjection
constexpr uintptr_t OFFSET_CAMERA_VIEWPROJ2 = 0xDC;       // Camera.ViewProjection2
*/
/* ==== Script / Modbase ==== */
/*
constexpr uintptr_t OFFSET_MODBASE_NETWORK = 0xF5E1E0;   // Modbase.Network
constexpr uintptr_t OFFSET_MODBASE_TICK = 0xF19418;   // Modbase.Tick
constexpr uintptr_t OFFSET_MODBASE_SCRIPTCTX = 0xF19398;   // Modbase.ScriptContext
constexpr uintptr_t OFFSET_SCRIPTCTX_CONSTTABLE = 0x68;       // ScriptContext.ConstantTable
*/

/* ==== Skeleton / Anim ==== */
/*
constexpr uintptr_t OFFSET_INFECTED_SKELETON = 0x678;      // DayZInfected.Skeleton
constexpr uintptr_t OFFSET_SKELETON_ANIMCLASS2 = 0x28;       // Skeleton.AnimClass2
constexpr uintptr_t OFFSET_ANIMCLASS_ANIMCOMP = 0xB0;       // AnimClass.AnimComponent
constexpr uintptr_t OFFSET_ANIMCLASS_MATRIXARRAY = 0xBF0;      // AnimClass.MatrixArray
constexpr uintptr_t OFFSET_ANIMCLASS_MATRIXB = 0x54;       // AnimClass.MatrixB

constexpr uintptr_t OFFSET_WEAPON_INDEX = 0x6B0;      // Weapon.WeaponIndex
constexpr uintptr_t OFFSET_WEAPON_INFOSIZE = 0x6BC;      // Weapon.WeaponInfoSize / MuzzleCount (совпадает)
constexpr uintptr_t OFFSET_WEAPON_MUZZLECOUNT = 0x6BC;      // Weapon.MuzzleCount
constexpr uintptr_t OFFSET_MAG_TYPE = 0x180;      // Magazine.MagazineType
constexpr uintptr_t OFFSET_MAG_BULLETLIST = 0xE00;      // Magazine.BulletList
constexpr uintptr_t OFFSET_MAG_BULLETLIST2 = 0x5A8;      // Magazine.BulletList2
constexpr uintptr_t OFFSET_AMMO_INITSPEED = 0x364;      // AmmoType.InitSpeed
constexpr uintptr_t OFFSET_AMMO_AIRFRICTION = 0x3B4;      // AmmoType.AirFriction
*/

/* ==== Имена, логирование и утилиты ==== */
std::string XorEncrypt(const std::string & input, const std::string & key);
std::string Base64Encode(const std::string & in);
extern std::string VerSVG;
extern std::string Goldberg_UID_SC;
extern int hostport;
extern int Port_Panel_Registered;
extern bool GameProjectdayzzona;
struct CachedMessage { std::chrono::steady_clock::time_point time; };
extern std::unordered_map<size_t, CachedMessage> messageCache;

extern std::string Name_Dll;
extern std::string hostsc;
extern std::string Name_Launcher;
extern std::string Name_Launcher2;
extern std::string Name_Window;

extern std::string Name_Game;
extern std::string Name_Game2;
extern std::string Name_GameEXE;
extern std::string Name_GameEXE2;

extern std::mutex cacheMutex;
static const wchar_t* ProccesMy[] = { L"dayzavr dayz.exe", L"dayzzona launcher.exe", L"system.windows.group.dll" };
void LogTest(const std::string& message);
bool IsGameRIP(uintptr_t rip);
bool IsValidAddress(uintptr_t addr);
void ReadGoldbergUIDStart(const std::string& relativePath);
void ReadSteamUIDStart();
void LogFormat(const char* format, ...);
void Log(const std::string& message);
bool SafeReadPtr(uintptr_t addr, uintptr_t& out);
std::string GetSecureIdentifier();
void SelectAvailableRegion();
