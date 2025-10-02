#include "Hooks.h"

#include "Manager.h"

namespace Hooks
{
	struct detail
	{
		static const char* GetGameVersionImpl()
		{
			using func_t = decltype(&GetGameVersionImpl);
			static REL::Relocation<func_t> func{ RELOCATION_ID(15485, 15650) };
			return func();
		}

		static REL::Version GetGameVersion()
		{
			std::stringstream            ss(GetGameVersionImpl());
			std::string                  token;
			std::array<std::uint16_t, 4> version{};

			for (std::size_t i = 0; i < 4 && std::getline(ss, token, '.'); ++i) {
				version[i] = static_cast<std::uint16_t>(std::stoi(token));
			}

			return REL::Version(version);
		}
	};

	struct TriggerMainMenuMusic
	{
		static bool thunk()
		{
			if (Manager::GetSingleton()->IsPlayingVideoAudio()) {
				return true;
			}

			return func();
		}
		static inline REL::Relocation<decltype(thunk)> func;
	};

	void Install()
	{
		const auto gameVersion = detail::GetGameVersion();

		std::array targets{
			std::make_pair(RELOCATION_ID(51238, 52110), (gameVersion >= SKSE::RUNTIME_SSE_1_6_629 && gameVersion <= SKSE::RUNTIME_SSE_1_6_640 ?
																0x22 :
																OFFSET(0x19, 0x2A))),

			std::make_pair(RELOCATION_ID(51259, 52137), OFFSET(0xFD, 0x2DD)),
		};

		for (auto& [id, offset] : targets) {
			REL::Relocation<std::uintptr_t> target{ id, offset };
			stl::write_thunk_call<TriggerMainMenuMusic>(target.address());
		}
	}
}
