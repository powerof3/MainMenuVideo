#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define DIRECTINPUT_VERSION 0x0800
#define IMGUI_DEFINE_MATH_OPERATORS

#include "RE/Skyrim.h"
#include "REX/REX.h"
#include "SKSE/SKSE.h"

#include <barrier>
#include <d3d11.h>
#include <dxgi.h>
#include <latch>
#include <shared_mutex>
#include <shlobj.h>
#include <wrl/client.h>

#include <Mferror.h>
#include <audioclient.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mftransform.h>
#include <propvarutil.h>

#include <opencv4/opencv2/core.hpp>
#include <opencv4/opencv2/imgproc.hpp>
#include <opencv4/opencv2/videoio.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <xbyak/xbyak.h>

#include "imgui_impl_win32.h"
#include "imgui_internal.h"
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_stdlib.h>

#include <SimpleIni.h>
#undef ERROR

using namespace std::literals;
using namespace REX::STR::literals;

template <class T>
using ComPtr = Microsoft::WRL::ComPtr<T>;

using EventResult = RE::BSEventNotifyControl;

namespace stl
{
	template <class T>
	void write_thunk_call(std::uintptr_t a_src)
	{
		auto& trampoline = REL::GetTrampoline();
		T::func = trampoline.write_call<5>(a_src, T::thunk);
	}

	template <class F, class T>
	void write_vfunc()
	{
		REL::Relocation<std::uintptr_t> vtbl{ F::VTABLE[0] };
		T::func = vtbl.write_vfunc(T::idx, T::thunk);
	}

	template <class T, std::size_t BYTES>
	void hook_function_prologue(std::uintptr_t a_src)
	{
		struct Patch : Xbyak::CodeGenerator
		{
			Patch(std::uintptr_t a_originalFuncAddr, std::size_t a_originalByteLength)
			{
				// Hook returns here. Execute the restored bytes and jump back to the original function.
				for (size_t i = 0; i < a_originalByteLength; ++i) {
					db(*reinterpret_cast<std::uint8_t*>(a_originalFuncAddr + i));
				}

				jmp(ptr[rip]);
				dq(a_originalFuncAddr + a_originalByteLength);
			}
		};

		Patch p(a_src, BYTES);
		p.ready();

		auto& trampoline = REL::GetTrampoline();
		trampoline.write_jmp<5>(a_src, T::thunk);

		auto alloc = trampoline.allocate(p.getSize());
		std::memcpy(alloc, p.getCode(), p.getSize());

		T::func = reinterpret_cast<std::uintptr_t>(alloc);
	}

	inline std::wstring utf8_to_utf16(std::string_view a_str)
	{
		std::wstring str16;
		REX::UTF8_TO_UTF16(a_str, str16);
		return str16;
	}
}

namespace Runtime
{
	inline constexpr REL::Version SSE_1_7_99(1, 7, 99, 0);
	inline constexpr REL::Version MIN_ADDRESS_LIBRARY_V5 = SSE_1_7_99;

	[[nodiscard]] inline bool IsAtLeast1_7_99() noexcept
	{
		static bool result = REX::FModule::GetExecutingModule().GetFileVersion() >= Runtime::SSE_1_7_99;
		return result;
	}
}

#ifdef SKYRIM_AE
#	define OFFSET(se, ae) ae
#else
#	define OFFSET(se, ae) se
#endif

#include "Version.h"
