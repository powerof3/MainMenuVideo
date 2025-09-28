#include "Hooks.h"

#include "Manager.h"

namespace Hooks
{
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
		std::array targets{
			std::make_pair(RELOCATION_ID(51238, 52110), OFFSET(0x19, 0x2A)),
			std::make_pair(RELOCATION_ID(51259, 52137), OFFSET(0xFD, 0x2DD)),
		};

		for (auto& [id, offset] : targets) {
			REL::Relocation<std::uintptr_t> target{ id, offset };
			stl::write_thunk_call<TriggerMainMenuMusic>(target.address());
		}
	}
}
