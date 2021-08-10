/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 */

#pragma once

#include <stdint.h>

#ifndef IS_FXSERVER
#define ASSERT(x) __noop
#include <jitasm.h>

#include <memory>
#include <functional>

namespace hook
{
	template<typename ValueType, typename AddressType>
	inline void put(AddressType address, ValueType value)
	{
		//adjust_base(address); don't need this
		memcpy((void*)address, &value, sizeof(value));
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

template<typename T, typename AT>
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
#endif
}

#include "Hooking.Patterns.h"