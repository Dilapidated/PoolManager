/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 */

#pragma once

#include "Hooking.Patterns.h"
#include "jitasm.h"


namespace hook
{
	//find patterns in a specific module
	template<typename T = void>
	inline auto get_module_pattern(const char* modulename, std::string_view pattern_string, ptrdiff_t offset = 0)
	{
		auto moduleHandle = GetModuleHandle(modulename);

		if (moduleHandle != nullptr)
		{
			return pattern(moduleHandle, std::move(pattern_string)).get_first<T>(offset);
		}
	}

	template<typename AddressType>
	inline void nop(AddressType address, size_t length)
	{

		DWORD oldProtect;
		VirtualProtect((void*)address, length, PAGE_EXECUTE_READWRITE, &oldProtect);

		memset((void*)address, 0x90, length);

		VirtualProtect((void*)address, length, oldProtect, &oldProtect);
	}

	template<typename ValueType, typename AddressType>
	inline void put(AddressType address, ValueType value)
	{
		memcpy((void*)address, &value, sizeof(value));
	}

	template <typename ValueType, typename AddressType>
	inline void putVP(AddressType address, ValueType value)
	{


		DWORD oldProtect;
		VirtualProtect((void*)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect);

		memcpy((void*)address, &value, sizeof(value));

		VirtualProtect((void*)address, sizeof(value), oldProtect, &oldProtect);
	}
	void* AllocateFunctionStub(void* origin, void* function, int type);

	template<typename T>
	struct get_func_ptr
	{
		static void* get(T func)
		{
			return (void*)func;
		}
	};

	template<int Register, typename T, typename AT>
	inline std::enable_if_t<(Register < 8 && Register >= 0)> call_reg(AT address, T func)
	{
		LPVOID funcStub = AllocateFunctionStub((void*)GetModuleHandle(NULL), get_func_ptr<T>::get(func), Register);

		put<uint8_t>(address, 0xE8);
		put<int>((uintptr_t)address + 1, (intptr_t)funcStub - (intptr_t)address - 5);
	}

	template <typename T, typename AT>
	inline void call(AT address, T func)
	{
		call_reg<0>(address, func);
	}

	template<typename T>
	inline T get_call(T address)
	{
		intptr_t target = *(int32_t*)((uintptr_t)address + 1);
		target += ((uintptr_t)address + 5);

		return (T)target;
	}


	template<typename TTarget, typename T>
	inline void set_call(TTarget* target, T address)
	{
		*(T*)target = get_call(address);
	}

	template<typename TClass, typename TMember>
	struct get_func_ptr<TMember TClass::*>
	{
		static void* get(TMember TClass::* function)
		{
			return (void*)get_member(function);
		}
	};

	template<typename T, typename TAddr>
	inline T get_address(TAddr address)
	{
		intptr_t target = *(int32_t*)(ptrdiff_t)address;
		target += ((ptrdiff_t)address + 4);

		return (T)target;
	}

}