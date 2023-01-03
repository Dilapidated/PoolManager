#include "atPool.h"
#include "joaat.h"
#include <Hooking.h>
#include <MinHook.h>
#include <iostream>
#include <fstream>

class RageHashList
{
public:
	template<int Size>
	RageHashList(const char* (&list)[Size])
	{
		for (int i = 0; i < Size; i++)
		{
			m_lookupList.insert({ joaat::generate(list[i]), list[i] });
		}
	}

	inline std::string LookupHashString(uint32_t hash)
	{

		if (hash == NULL)
		{
			return "unknown";
		}

		auto it = m_lookupList.find(hash);
		if (it != m_lookupList.end())
		{
			return std::string(it->second);
		}

		char buffer[32];
		snprintf(buffer, std::size(buffer), "0x%08X", hash);
		return buffer;
	}

	inline std::string LookupHash(uint32_t hash)
	{
		if (hash == NULL)
		{
			return "unknown";
		}

		char buffer[32];
		snprintf(buffer, std::size(buffer), "0x%08X", hash);
		return buffer;
	}

private:
	std::map<uint32_t, std::string_view> m_lookupList;
};

int LogPercentUsageWarning = GetPrivateProfileInt("POOL_SETTINGS", "LogPercentUsageWarning", 0, ".\\PoolManager.ini");
int LogPercentUsageWarningAmount = GetPrivateProfileInt("POOL_SETTINGS", "LogPercentUsageWarningAmount", 50, ".\\PoolManager.ini");
int LogInitialPoolAmounts = GetPrivateProfileInt("POOL_SETTINGS", "LogInitialPoolAmounts ", 0, ".\\PoolManager.ini");

static std::string LastPoolLogged;
static int LastSizeLogged;

bool clearedLogs = false;

void cleanUpLogs()
{
	if (!clearedLogs)
	{
		if (LogInitialPoolAmounts != 0)
		{
			std::ofstream outfile;
			outfile.open("PoolManager_Startup.log", std::ofstream::out | std::ofstream::trunc);
			outfile.close();
		}

		if (LogPercentUsageWarning != 0)
		{
			std::ofstream outfile;
			outfile.open("PoolManager_UsageWarning.log", std::ofstream::out | std::ofstream::trunc);
			outfile.close();
		}

		clearedLogs = true;
	}
}

static std::map<uint32_t, atPoolBase*> g_pools;
static std::map<atPoolBase*, uint32_t> g_inversePools;
static std::map<std::string, UINT> g_intPools;
static std::multimap<UINT, std::string> g_intPoolsMulti;

static const char* poolEntriesTable[] = {
"actiontable_branches",
"actiontable_damages",
"actiontable_definitions",
"actiontable_facialanimsets",
"actiontable_homings",
"actiontable_impulses",
"actiontable_interrelations",
"actiontable_results",
"actiontable_rumbles",
"actiontable_stealthkills",
"actiontable_strikebones",
"actiontable_vfx",
"activeloadedinfo",
"activepersistentloadedinfo",
"aircraftflames",
"animatedbuilding",
"animscenes",
"animstore",
"atdscriptobjectnode",
"atdtransactionnode",
"attachmentextension",
"audioheap",
"blendshapestore",
"building",
"caicurvepoint",
"caihandlinginfo",
"cambasecamera",
"cambaseframeshaker",
"cambaseswitchhelper",
"cambientlookat",
"camcatchuphelper",
"camcollision",
"camcontrolhelper",
"camenvelope",
"camframeinterpolator",
"camhinthelper",
"caminconsistentbehaviourzoomhelper",
"camlookaheadhelper",
"camlookatdampinghelper",
"camoscillator",
"camsplinenode",
"camspringmount",
"camthirdpersonframeinterpolator",
"carmiksolver",
"carrec",
"cboatchasedirector",
"cbodylookiksolver",
"cbodylookiksolverproxy",
"cbodyrecoiliksolver",
"cbullet",
"cbullet::sbulletinstance",
"ccargen",
"ccargenforscenarios",
"cclimbhandholddetected",
"ccollectioninfo",
"ccombatdirector",
"ccombatinfo",
"ccombatsituation",
"ccoverfinder",
"cdefaultcrimeinfo",
"cdoorextension",
"cevent",
"ceventdecisionmaker",
"ceventdecisionmakermodifiablecomponent",
"ceventdecisionmakerresponsedynamic",
"ceventnetwork",
"cgamescripthandler",
"cgamescripthandlernetcomponent",
"cgamescripthandlernetwork",
"cgamescriptresource",
"cgpsnumnodesstored",
"cgrabhelper",
"chandlingobject",
"cinventoryitem",
"clandinggear_qkdfqq",
"clegiksolver",
"clegiksolverproxy",
"clightextension",
"clothstore",
"cmoveanimatedbuilding",
"cmoveobject",
"cmoveped",
"cmovevehicle",
"cnamedpatrolroute",
"collision_5plvhjd",
"combatmeleemanager_groups",
"combatmeleemanager_groupsmp",
"combatmountedmanager_attacks",
"compentity",
"cpathnoderoutesearchhelper",
"cpatrollink",
"cpatrolnode",
"cpickup",
"cpickupdata",
"cpickupplacement",
"cpickupplacementcustomscriptdata",
"cplayerinfo",
"cprioritizedclipsetbucket",
"cprioritizedclipsetrequest",
"cpropmanagementhelper",
"cregenerationinfo",
"crelationshipgroup",
"croadblock",
"crootslopefixupiksolver",
"cscenarioclusterspawnedtrackingdata",
"cscenarioinfo",
"cscenariopoint",
"cscenariopointchainuseinfo",
"cscenariopointextradata",
"cscriptentityextension",
"cspawnpointoverrideextension",
"cspclusterfsmwrapper",
"cstuntjump",
"ctacticalanalysis",
"ctask",
"ctaskconversationhelper",
"ctasksequencelist",
"ctaskusescenarioentityextension",
"ctaskvehicleserialiserbase",
"ctorsoiksolver",
"ctorsoreactiksolver",
"ctorsovehicleiksolver",
"ctorsovehicleiksolverproxy",
"cutscenestore",
"cvehiclechasedirector",
"cvehiclecliprequesthelper",
"cvehiclecombatavoidancearea",
"cvehicleintelligence_8xo47n9",
"cvehiclestreamrendergfx",
"cvehiclestreamrequestgfx",
"cweapon",
"cweaponcomponent",
"decorator",
"decoratorextension",
"drawablestore",
"dummy",
"dummy object",
"dwdstore",
"entitybatch",
"explosiontype",
"exprdictstore",
"fraginstgta",
"fraginstnmgta",
"fragmentstore",
"framefilterstore",
"fwanimdirector",
"fwanimdirectorcomponentcreature",
"fwanimdirectorcomponentexpressions",
"fwanimdirectorcomponentfacialrig",
"fwanimdirectorcomponentmotiontree",
"fwanimdirectorcomponentmove",
"fwanimdirectorcomponentragdoll",
"fwanimdirectorcomponentsyncedscene",
"fwarchetypepooledmap",
"fwclothcollisionsextension",
"fwdynamicarchetypecomponent",
"fwdynamicentitycomponent",
"fwentitycontainer",
"fwlodnode",
"fwmatrixtransform",
"fwquaterniontransform",
"fwscriptguid",
"fwsimpletransform",
"gameplayerbroadcastdatahandler_remote",
"grassbatch",
"handlingdata",
"incidents",
"instancebuffer",
"interiorinst",
"interiorproxy",
"iplstore",
"itemset",
"itemsetbuffer",
"known",
"known refs",
"lightentity",
"mapdataloadednode",
"mapdatastore",
"maptypesstore",
"maxloadedinfo",
"maxloadrequestedinfo",
"maxnonregionscenariopointspatialobjects",
"metadatastore",
"musicaction",
"musicevent",
"naenvironmentgroup",
"navmeshes",
"navmeshroute",
"netshoptransactions",
"networkcrewdatamgr",
"networkdefstore",
"networkentityareas",
"object",
"objectintelligence",
"occlusioninteriorinfo",
"occlusionpathnode",
"occlusionportalentity",
"occlusionportalinfo",
"orders",
"patrolroute",
"pedintelligence",
"pedprop render data",
"pedprop req data",
"peds",
"phinstgta",
"physicsbounds",
"pmstore",
"pointroute",
"portalinst",
"posematcherstore",
"ptfxassetstore",
"ptfxsortedentity",
"quadtreenodes",
"refs",
"ropedata",
"scaleformmgrarray",
"scaleformstore",
"scenariocargensperregion",
"scenariopoint",
"scenariopointentity",
"scenariopointsandedgesperregion",
"scenariopointworld",
"scriptshapetestresult",
"scriptstore",
"shapetesttaskdata",
"staticbounds",
"streamped render data",
"streamped req data",
"syncedscenes",
"targetting",
"tasksequenceinfo",
"tcbox",
"trafficlightinfos",
"txdstore",
"vehicleglasscomponententity",
"vehicles",
"vehiclescenarioattractors",
"vehiclestreamrender",
"vehiclestreamrequest",
"vehiclestruct",
"wheels",
"wptrec",
"vehicleaudioentity",
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


	if (LogPercentUsageWarning != 0)
	{
		if ((float)pool->GetCount() / (float)pool->GetSize() * 100.00f > LogPercentUsageWarningAmount)
		{
			auto it = g_inversePools.find(pool);

			uint32_t poolHash = 0;
			if (g_inversePools.count(pool) != 0)
				poolHash = it->second;

			std::string poolName = poolEntries.LookupHashString(poolHash);
			std::string poolNameHash = poolEntries.LookupHash(poolHash);

			auto comparisons = g_intPoolsMulti.equal_range(pool->GetSize());

			if (poolName == "unknown" && comparisons.first != comparisons.second)
			{
				poolName = "unknown - possible pool names with same value: ";;

				for (auto comparisonsr = comparisons.first; comparisonsr != comparisons.second; ++comparisonsr)
				{
					poolName = poolName + " " + comparisonsr->second;
				}
			}

			auto poolSize = pool->GetSize();
			auto poolCount = pool->GetCount();
			float percent = (float)poolCount / (float)poolSize;

			std::ofstream outfile;
			outfile.open("PoolManager_UsageWarning.log", std::ios_base::app);

			if (LastPoolLogged == poolName && LastSizeLogged == poolSize)
			{
				outfile << "(count:" << poolCount << "/"
					<< "size:" << poolSize << ") poolUsage :" << percent * 100.00f << "%" << std::endl;
			}
			else
			{
				outfile << std::endl << "poolName: " << poolName.c_str() << std::endl
					<< "poolHash: " << poolNameHash.c_str() << std::endl
					<< "poolSize: " << poolSize << std::endl
					<< "poolCount: " << poolCount << std::endl
					<< "poolUsage: " << percent * 100.00f << "%" << std::endl
					<< "poolPointer: " << pool << std::endl;
				LastPoolLogged = poolName;
				LastSizeLogged = poolSize;
			}
		}
	}

	if (!value)
	{
		auto it = g_inversePools.find(pool);

		uint32_t poolHash = 0;
		if (g_inversePools.count(pool) != 0)
			poolHash = it->second;

		std::string poolName = poolEntries.LookupHashString(poolHash);
		std::string poolNameHash = poolEntries.LookupHash(poolHash);

		auto comparisons = g_intPoolsMulti.equal_range(pool->GetSize());
		if (poolName == "unknown" && comparisons.first != comparisons.second)
		{
			poolName = "unknown - possible pool names with same value: ";;

			for (auto comparisonsr = comparisons.first; comparisonsr != comparisons.second; ++comparisonsr)
			{
				poolName = poolName + " " + comparisonsr->second;
			}
		}

		std::ofstream outfile;
		outfile.open("PoolManager_Crash.log", std::ios_base::app);
		outfile << "poolName: " << poolName.c_str() << std::endl
			<< "poolHash: " << poolNameHash.c_str() << std::endl
			<< "poolSize: " << pool->GetSize() << std::endl
			<< "poolPointer: " << pool << std::endl
			<< std::endl;
		outfile.close();

		char buff[256];
		std::string extraWarning;
		if (poolName.find("0x") == std::string::npos)
		{
			sprintf_s(buff, "\nYou need to raise %s's pool size in update.rpf/common/data/gameconfig.xml", poolName.c_str());
			extraWarning = buff;
		}

		sprintf_s(buff, "%s pool crashed the game! \nPool hash: %s \nCurrent pool size: %llu \nCrash saved to PoolManager_Crash.log %s", poolName.c_str(), poolNameHash.c_str(), pool->GetSize(), extraWarning.c_str());
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


typedef std::uint32_t(*GetSizeOfPool_t)(PVOID _this, std::uint32_t poolHash, std::uint32_t defaultSize);
GetSizeOfPool_t g_origSizeOfPool = nullptr;

std::uint32_t GetSizeOfPool(PVOID _this, std::uint32_t poolHash, std::uint32_t defaultSize)
{

	auto value = g_origSizeOfPool(_this, poolHash, defaultSize);
	std::string poolName = poolEntries.LookupHashString(poolHash);
	std::string poolNameHash = poolEntries.LookupHash(poolHash);

	auto it = g_intPools.find(poolName);
	if (it == g_intPools.end())
	{
		g_intPools.insert({ poolName, value });
		if (LogInitialPoolAmounts != 0)
		{
			if (poolName == poolNameHash)
			{
				poolName = "unknown";
			}
			std::ofstream outfile;
			outfile.open("PoolManager_Startup.log", std::ios_base::app);
			outfile << "poolName: " << poolName.c_str() << std::endl
				<< "poolHash: " << poolNameHash.c_str() << std::endl
				<< "poolSize: " << value << std::endl
				<< std::endl;
		}
	}
	
	return value;
}

static struct MhInit
{
	MhInit()
	{
		MH_Initialize();
	}
} mhInit;

void InitializeMod()
{
	// Clean up logging
	cleanUpLogs();

	auto registerPool = [](hook::pattern_match match, int callOffset, uint32_t hash, bool isAssetStore)
	{
		struct : jitasm::Frontend
		{
			uint32_t hash;
			uint64_t origFn;
			bool isAssetStore;

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
				if (isAssetStore == true) // Only set to true in registerNamedPool. Hook asset store constructor, but with this+0x38 so to get the address of the pool field.
					add(rcx, 0x38);

				mov(edx, hash);

				mov(rax, (uint64_t)&SetPoolFn);
				call(rax);

				add(rsp, 0x38);

				ret();
			}
		} *stub = new std::remove_pointer_t<decltype(stub)>();

		stub->hash = hash;
		stub->isAssetStore = isAssetStore;

		auto call = match.get<void>(callOffset);
		hook::set_call(&stub->origFn, call);
		hook::call(call, stub->GetCode());
	};

	auto registerPools = [&](hook::pattern& patternMatch, int callOffset, int hashOffset)
	{
		for (size_t i = 0; i < patternMatch.size(); i++)
		{
			auto match = patternMatch.get(i);
			registerPool(match, callOffset, *match.get<uint32_t>(hashOffset), false);
		}
	};

	auto registerNamedPools = [&](hook::pattern& patternMatch, int callOffset, int nameOffset)
	{
		for (size_t i = 0; i < patternMatch.size(); i++)
		{
			auto match = patternMatch.get(i);
			char* name = hook::get_address<char*>(match.get<void*>(nameOffset));
			registerPool(match, callOffset, joaat::generate(name), true);
		}
	};

	auto registerPoolsPatch = [&](hook::pattern& patternMatch, int callOffset, int hashOffset) // used to avoid crashing with specific pools
	{
		size_t from = 0;
		size_t to = patternMatch.size();
		for (size_t i = from; i < to; i++)
		{
			auto match = patternMatch.get(i);
			if (poolEntries.LookupHash(*match.get<uint32_t>(hashOffset)) == "0x5F91F738") continue; // crashes with this pool (0x5F91F738 = netshoptransactions)
			registerPool(match, callOffset, *match.get<uint32_t>(hashOffset), false);
		}
	};

	// Find initial pools
	registerPoolsPatch(hook::pattern("BA ? ? ? ? 41 B8 ? ? ? 00 E8 ? ? ? ? 4C 8D 05"), 0x2C, 1);
	registerPools(hook::pattern("C6 BA ? ? ? ? E8 ? ? ? ? 4C 8D 05"), 0x27, 2);
	registerPools(hook::pattern("BA ? ? ? ? E8 ? ? ? ? C6 ? ? ? 01 4C"), 0x2F, 1);
	registerPools(hook::pattern("BA ? ? ? ? 41 B8 ? 00 00 00 E8 ? ? ? ? C6"), 0x35, 1);
	registerPools(hook::pattern("44 8B C0 BA ? ? ? ? E8 ? ? ? ? 4C 8D 05"), 0x25, 4);

	registerNamedPools(hook::pattern("48 8D 15 ? ? ? ? 45 8D 41 ? 48 8B ? C7"), 0x15, 0x3); // fwAssetStores

	// Get Initial Pool Sizes
	if (GetModuleHandle("ScriptHookV.dll") != nullptr) //If using SHV hook into SHV and get pools
	{
		auto loc = hook::get_module_pattern<uint8_t>("ScriptHookV.dll", "40 53 48 83 EC ? 0F");
		MH_CreateHook(loc, GetSizeOfPool, (void**)&g_origSizeOfPool);
	}
	else
	{
		auto addr = hook::get_call(hook::get_pattern("E8 ? ? ? ? 48 8D 4F 38 41 B0 01"));
		MH_CreateHook(addr, GetSizeOfPool, (void**)&g_origSizeOfPool);
	}

	// Pool Allocate Wrap
	MH_CreateHook(hook::get_pattern("18 83 F9 FF 75 03 33 C0 C3 41", -6), PoolAllocateWrap, (void**)&g_origPoolAllocate);

	// Pool Dtor Wrap
	MH_CreateHook(hook::get_pattern("7E 38 F7 41 20 00 00 00 C0 74 1B", -0xD), PoolDtorWrap, (void**)&g_origPoolDtor);

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
