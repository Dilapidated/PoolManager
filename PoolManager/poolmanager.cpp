
#include "atPool.h"
#include <Hooking.h>
#include <MinHook.h>
#include <iostream>
#include <Utils.h>

class RageHashList
{
public:
	template<int Size>
	RageHashList(const char* (&list)[Size])
	{
		for (int i = 0; i < Size; i++)
		{
			m_lookupList.insert({ HashString(list[i]), list[i] });
		}
	}

	inline std::string LookupHash(uint32_t hash)
	{
		auto it = m_lookupList.find(hash);

		if (it != m_lookupList.end())
		{
			return std::string(it->second);
		}

		char buffer[32];
		snprintf(buffer, std::size(buffer), "0x%08x", hash);
		return buffer;
	}

private:
	std::map<uint32_t, std::string_view> m_lookupList;
};

static std::map<uint32_t, atPoolBase*> g_pools;
static std::map<atPoolBase*, uint32_t> g_inversePools;

static const char* poolEntriesTable[] = {
	"AnimatedBuilding",
	"AttachmentExtension",
	"AudioHeap",
	"BlendshapeStore",
	"Building",
	"carrec",
	"CBoatChaseDirector",
	"CVehicleCombatAvoidanceArea",
	"CCargen",
	"CCargenForScenarios",
	"CCombatDirector",
	"CCombatInfo",
	"CCombatSituation",
	"CCoverFinder",
	"CDefaultCrimeInfo",
	"CTacticalAnalysis",
	"CTaskUseScenarioEntityExtension",
	"AnimStore",
	"CGameScriptResource",
	"ClothStore",
	"CombatMeleeManager_Groups",
	"CombatMountedManager_Attacks",
	"CompEntity",
	"CPrioritizedClipSetBucket",
	"CPrioritizedClipSetRequest",
	"CRoadBlock",
	"CStuntJump",
	"CScenarioInfo",
	"CScenarioPointExtraData",
	"CutsceneStore",
	"CScriptEntityExtension",
	"CVehicleChaseDirector",
	"CVehicleClipRequestHelper",
	"CPathNodeRouteSearchHelper",
	"CGrabHelper",
	"CGpsNumNodesStored",
	"CClimbHandHoldDetected",
	"CAmbientLookAt",
	"DecoratorExtension",
	"DrawableStore",
	"Dummy Object",
	"DwdStore",
	"EntityBatch",
	"GrassBatch",
	"ExprDictStore",
	"FrameFilterStore",
	"FragmentStore",
	"GamePlayerBroadcastDataHandler_Remote",
	"InstanceBuffer",
	"InteriorInst",
	"InteriorProxy",
	"IplStore",
	"MaxLoadedInfo",
	"MaxLoadRequestedInfo",
	"ActiveLoadedInfo",
	"ActivePersistentLoadedInfo",
	"Known Refs",
	"LightEntity",
	"MapDataLoadedNode",
	"MapDataStore",
	"MapTypesStore",
	"MetaDataStore",
	"NavMeshes",
	"NetworkDefStore",
	"NetworkCrewDataMgr",
	"Object",
	"OcclusionInteriorInfo",
	"OcclusionPathNode",
	"OcclusionPortalEntity",
	"OcclusionPortalInfo",
	"Peds",
	"CWeapon",
	"phInstGta",
	"PhysicsBounds",
	"CPickup",
	"CPickupPlacement",
	"CPickupPlacementCustomScriptData",
	"CRegenerationInfo",
	"PortalInst",
	"PoseMatcherStore",
	"PMStore",
	"PtFxSortedEntity",
	"PtFxAssetStore",
	"QuadTreeNodes",
	"ScaleformStore",
	"ScaleformMgrArray",
	"ScriptStore",
	"StaticBounds",
	"tcBox",
	"TrafficLightInfos",
	"TxdStore",
	"Vehicles",
	"VehicleStreamRequest",
	"VehicleStreamRender",
	"VehicleStruct",
	"HandlingData",
	"wptrec",
	"fwLodNode",
	"CTask",
	"CEvent",
	"CMoveObject",
	"CMoveAnimatedBuilding",
	"atDScriptObjectNode",
	"fwDynamicArchetypeComponent",
	"fwDynamicEntityComponent",
	"fwEntityContainer",
	"fwMatrixTransform",
	"fwQuaternionTransform",
	"fwSimpleTransform",
	"ScenarioCarGensPerRegion",
	"ScenarioPointsAndEdgesPerRegion",
	"ScenarioPoint",
	"ScenarioPointEntity",
	"ScenarioPointWorld",
	"MaxNonRegionScenarioPointSpatialObjects",
	"ObjectIntelligence",
	"VehicleScenarioAttractors",
	"AircraftFlames",
	"CScenarioPointChainUseInfo",
	"CScenarioClusterSpawnedTrackingData",
	"CSPClusterFSMWrapper",
	"fwArchetypePooledMap",
	"CTaskConversationHelper",
	"SyncedScenes",
	"AnimScenes",
	"CPropManagementHelper",
	"ActionTable_Definitions",
	"ActionTable_Results",
	"ActionTable_Impulses",
	"ActionTable_Interrelations",
	"ActionTable_Homings",
	"ActionTable_Damages",
	"ActionTable_StrikeBones",
	"ActionTable_Rumbles",
	"ActionTable_Branches",
	"ActionTable_StealthKills",
	"ActionTable_Vfx",
	"ActionTable_FacialAnimSets",
	"NetworkEntityAreas",
	"NavMeshRoute",
	"CScriptEntityExtension",
	"AnimStore",
	"CutSceneStore",
	"OcclusionPathNode",
	"OcclusionPortalInfo",
	"CTask",
	"OcclusionPathNode",
	"OcclusionPortalInfo",
#include "gta_vtables.h"
};

static RageHashList poolEntries(poolEntriesTable);

static atPoolBase* SetPoolFn(atPoolBase* pool, uint32_t hash)
{
	g_pools[hash] = pool;
	g_inversePools.insert({ pool, hash });

	return pool;
}

static void(*g_origPoolDtor)(atPoolBase*);

static void PoolDtorWrap(atPoolBase* pool)
{
	auto hashIt = g_inversePools.find(pool);

	if (hashIt != g_inversePools.end())
	{
		auto hash = hashIt->second;

		g_pools.erase(hash);
		g_inversePools.erase(pool);
	}

	return g_origPoolDtor(pool);
}

static void* (*g_origPoolAllocate)(atPoolBase*);

static void* PoolAllocateWrap(atPoolBase* pool)
{
	void* value = g_origPoolAllocate(pool);

	if (!value)
	{
		auto it = g_inversePools.find(pool);
		std::string poolName = "Unknown";

		if (it != g_inversePools.end())
		{
			uint32_t poolHash = it->second;

			poolName = poolEntries.LookupHash(poolHash);
		}

		char buff[256];
		std::string extraWarning;
		if (poolName.find("0x") == std::string::npos)
		{
			sprintf_s(buff, "\nYou need to raise %s's pool size in update.rpf/common/data/gameconfig.xml", poolName.c_str());
			extraWarning = buff;
		}

		sprintf_s(buff, "%s pool crashed the game! \nCurrent pool size: %llu%s", poolName.c_str(), pool->GetSize(), extraWarning.c_str());
		std::cout << buff;
		HWND hWnd = FindWindow("grcWindow", NULL);
		int msgboxID = MessageBox(hWnd, buff, "PoolManager.asi", MB_OK | MB_ICONERROR);

		switch (msgboxID)
		{
		case IDOK:
			exit(0);
			break;
		}
	}

	return value;
}

static void(*g_origLoadObjectsNow)(void*, bool);

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;

bool(*g_origShouldWriteToPlayer)(void* a1, void* a2, int playerIdx, int a4);

static bool ShouldWriteToPlayerWrap(void* a1, void* a2, int playerIdx, int a4)
{
	if (playerIdx == 31)
	{
		//return true;
	}

	return g_origShouldWriteToPlayer(a1, a2, playerIdx, a4);
}


void InitializeMod()
{

	auto registerPools = [](hook::pattern& patternMatch, int callOffset, int hashOffset)
	{
		for (size_t i = 0; i < patternMatch.size(); i++)
		{
			auto match = patternMatch.get(i);
			auto hash = *match.get<uint32_t>(hashOffset);

			struct : jitasm::Frontend
			{
				uint32_t hash;
				uint64_t origFn;

				void InternalMain() override
				{
					sub(rsp, 0x38);

					mov(rax, qword_ptr[rsp + 0x38 + 0x28]);
					mov(qword_ptr[rsp + 0x20], rax);

					mov(rax, qword_ptr[rsp + 0x38 + 0x30]);
					mov(qword_ptr[rsp + 0x28], rax);

					mov(rax, origFn);
					call(rax);

					mov(rcx, rax);
					mov(edx, hash);

					mov(rax, (uint64_t)& SetPoolFn);
					call(rax);

					add(rsp, 0x38);

					ret();
				}
			}*stub = new std::remove_pointer_t<decltype(stub)>();

			stub->hash = hash;

			auto call = match.get<void>(callOffset);
			hook::set_call(&stub->origFn, call);
			hook::call(call, stub->GetCode());
		}
	};

	// find initial pools
	registerPools(hook::pattern("BA ? ? ? ? 41 B8 ? ? ? 00 E8 ? ? ? ? 4C 8D 05"), 0x2C, 1);
	registerPools(hook::pattern("C6 BA ? ? ? ? E8 ? ? ? ? 4C 8D 05"), 0x27, 2);
	registerPools(hook::pattern("BA ? ? ? ? E8 ? ? ? ? C6 ? ? ? 01 4C"), 0x2F, 1);
	registerPools(hook::pattern("BA ? ? ? ? 41 B8 ? 00 00 00 E8 ? ? ? ? C6"), 0x35, 1);

	// min hook
	MH_CreateHook(hook::get_pattern("18 83 F9 FF 75 03 33 C0 C3 41", -6), PoolAllocateWrap, (void**)& g_origPoolAllocate);

	// pool dtor wrap
	MH_CreateHook(hook::get_pattern("7E 38 F7 41 20 00 00 00 C0 74 1B", -0xD), PoolDtorWrap, (void**)& g_origPoolDtor);

	MH_EnableHook(MH_ALL_HOOKS);

}

BOOL WINAPI DllMain(_In_ void* _DllHandle, _In_ unsigned long _Reason, _In_opt_ void* _Reserved)
{
	if (_Reason == DLL_PROCESS_ATTACH)
	{
		InitializeMod();
	}
	return TRUE;
}