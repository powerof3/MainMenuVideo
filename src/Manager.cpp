#include "Manager.h"

#include "Hooks.h"
#include "ImGui/Renderer.h"
#include "ImGui/Util.h"

void Manager::Register()
{
	LoadSettings();
	GetVideoList();

	if (videoPaths.empty()) {
		logger::info("No videos found in Data\\MainMenuVideo...");
		return;
	} else {
		logger::info("{} videos found in Data\\MainMenuVideo.", videoPaths.size());
	}

	RE::UI::GetSingleton()->AddEventSink<RE::MenuOpenCloseEvent>(this);

	SKSE::AllocTrampoline(42);
	ImGui::Renderer::Install();
	Hooks::Install();
}

void Manager::LoadSettings()
{
	constexpr auto path = L"Data/SKSE/Plugins/po3_MainMenuVideo.ini";

	CSimpleIniA ini;
	ini.SetUnicode();

	ini.LoadFile(path);

	ini::get_value(ini, showDebugInfo, "Settings", "bDebugStats", ";Display video stats including elapsed time and frame rate");
	ini::get_value(ini, showBackground, "Settings", "bDrawSolidBackground", ";Draw a solid black background behind the video to hide main menu logo and other elements");
	ini::get_value(ini, playVideoAudio, "Settings", "bPlayAudio", ";Replace main menu music with the video's audio track");

	(void)ini.SaveFile(path);
}

void Manager::Draw()
{
	const static auto center = ImGui::GetNativeViewportCenter();
	const static auto screenSize = ImGui::GetNativeViewportSize();
	const auto        videoSize = videoPlayer.GetNativeSize();

	ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5, 0.5));
	ImGui::SetNextWindowSize(videoSize);

	ImGui::Begin("##MainMenuVideo", nullptr, ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground);
	{
		if (videoSize != screenSize && showBackground) {
			ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0, 0), screenSize, IM_COL32_BLACK);
		}
		ImGui::Image(videoPlayer.GetTextureID(), videoSize);
		if (showDebugInfo) {
			videoPlayer.ShowDebugInfo();
		}
	}
	ImGui::End();
}

void Manager::Update()
{
	if (auto renderer = RE::BSGraphics::Renderer::GetSingleton()) {
		if (const auto context = reinterpret_cast<ID3D11DeviceContext*>(renderer->data.context)) {
			videoPlayer.Update(context, ImGui::GetIO().DeltaTime);  // RE::BSTimer::GetSingleton()->realTimeDelta doesn't init properly until main menu loads
		}
	}
}

bool Manager::LoadVideo()
{
	if (videoPaths.empty()) {
		return false;
	}

	if (auto renderer = RE::BSGraphics::Renderer::GetSingleton()) {
		if (auto device = reinterpret_cast<ID3D11Device*>(renderer->data.forwarder)) {
			std::size_t numVideos = videoPaths.size();

			if (numVideos == 1) {
				if (videoPlayer.LoadVideo(device, videoPaths[0].string(), playVideoAudio)) {
					selectedIndex = 0;
					return true;
				}
				return false;
			}

			static clib_util::RNG rng{};
			std::size_t           randIndex = rng.generate<std::size_t>(0, numVideos - 2);
			std::size_t           nextIndex = (randIndex >= selectedIndex) ? randIndex + 1 : randIndex;

			if (videoPlayer.LoadVideo(device, videoPaths[nextIndex].string(), playVideoAudio)) {
				selectedIndex = nextIndex;
				return true;
			}

			// fallback
			return videoPlayer.LoadVideo(device, videoPaths[selectedIndex].string(), playVideoAudio);
		}
	}

	return false;
}

bool Manager::IsPlayingVideo() const
{
	return videoPlayer.IsPlaying();
}

bool Manager::IsPlayingVideoAudio() const
{
	return videoPlayer.IsPlayingAudio();
}

void Manager::GetVideoList()
{
	constexpr std::string_view directory = "Data\\MainMenuVideo"sv;

	std::error_code ec;
	if (!std::filesystem::exists(directory, ec)) {
		return;
	}

	for (auto& i : std::filesystem::directory_iterator(directory)) {
		videoPaths.push_back({ i.path().string() });
	}
}

EventResult Manager::ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*)
{
	if (!a_evn) {
		return EventResult::kContinue;
	}

	const auto& menuName = a_evn->menuName;

	if (menuName == RE::MainMenu::MENU_NAME) {
		mainMenuClosed = !a_evn->opening;
	} else if (menuName == RE::LoadingMenu::MENU_NAME) {
		if (a_evn->opening) {
			if (firstBoot) {
				firstBoot = false;
				Manager::GetSingleton()->LoadVideo();
			} else if (mainMenuClosed) {
				if (videoPlayer.IsPlaying()) {
					videoPlayer.Reset();  // main menu -> loading screen -> game
				}
			}
		}
	} else if (menuName == RE::FaderMenu::MENU_NAME) {
		if (a_evn->opening && RE::Main::GetSingleton()->resetGame) {
			LoadVideo();  // game -> quit to main menu
		}
	}

	return EventResult::kContinue;
}
