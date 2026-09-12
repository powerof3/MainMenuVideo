#pragma once

#include "Manager.h"

namespace ImGui::Renderer
{
	inline std::atomic initialized{ false };

	template <class T>
	struct PostDisplay
	{
		static void thunk(T* a_menu)
		{
			// Skip if Imgui is not loaded
			if (!initialized.load() || !Manager::GetSingleton()->IsPlayingVideo()) {
				return func(a_menu);
			}

			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			{
				//trick imgui into rendering at game's real resolution (ie. if upscaled with Display Tweaks)
				static const auto screenSize = RE::BSGraphics::Renderer::GetScreenSize();

				auto& io = ImGui::GetIO();
				io.DisplaySize.x = static_cast<float>(screenSize.width);
				io.DisplaySize.y = static_cast<float>(screenSize.height);
			}
			ImGui::NewFrame();
			{
				Manager::GetSingleton()->Draw();
			}
			ImGui::EndFrame();
			ImGui::Render();
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

			func(a_menu);
		}
		static inline REL::Relocation<decltype(thunk)> func;
		static inline std::size_t                      idx{ 0x6 };
	};

	void Install();
}
