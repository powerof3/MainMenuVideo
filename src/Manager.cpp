#include "Manager.h"

#include "Hooks.h"
#include "ImGui/Renderer.h"
#include "ImGui/Util.h"

void Manager::Register()
{
	logger::info("Loading settings...");
	LoadSettings();
	logger::info("Getting video list...");
	GetVideoList();

	if (videoPaths.empty()) {
		logger::info("No videos found in Data\\MainMenuVideo...");
		return;
	} else {
		const auto numVideos = videoPaths.size();
		logger::info("{} videos found in Data\\MainMenuVideo.", numVideos);

		if (numVideos == 1 && videoPlayer.GetPlaybackMode() == PLAYBACK_MODE::kPlayNext) {
			videoPlayer.SetPlaybackMode(PLAYBACK_MODE::kLoop);
		}
	}

	RE::UI::GetSingleton()->AddEventSink<RE::MenuOpenCloseEvent>(this);
	if (auto scriptEventHolder = RE::ScriptEventSourceHolder::GetSingleton()) {
		scriptEventHolder->AddEventSink<RE::TESDeathEvent>(this);
	}

	SKSE::AllocTrampoline(42);
	ImGui::Renderer::Install();
	Hooks::Install();
}

void Manager::CompatibilityCheck()
{
	heyYouYoureFinallyAwake = GetModuleHandleA("po3_HeyYouYoureFinallyAwake.dll") != nullptr;
	logger::info("po3_HeyYoureFinallyAwake.dll installed : {}", heyYouYoureFinallyAwake);
}

void Manager::LoadSettings()
{
	constexpr auto path = L"Data/SKSE/Plugins/po3_MainMenuVideo.ini";

	CSimpleIniA ini;
	ini.SetUnicode();

	ini.LoadFile(path);

	PLAYBACK_MODE mode{ PLAYBACK_MODE::kLoop };
	ini::get_value(ini, mode, "Settings", "iPlaybackMode", ";0 - Play once, 1 - Play next video, 2 - Loop current video");
	videoPlayer.SetPlaybackMode(mode);

	ini::get_value(ini, playVideoAudio, "Settings", "bPlayAudio", ";Replace main menu music with the video's audio track");
	ini::get_value(ini, showDebugInfo, "Settings", "bDebugStats", ";Display video stats including elapsed time and frame rate");

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
		ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0, 0), screenSize, IM_COL32_BLACK);
		ImGui::Image(videoPlayer.GetTextureID(), videoSize);
		if (showDebugInfo) {
			videoPlayer.ShowDebugInfo();
		}
	}
	ImGui::End();
}

void Manager::Update()
{
	if (!IsPlayingVideo()) {
		return;
	}

	if (auto renderer = RE::BSGraphics::Renderer::GetSingleton()) {
		if (const auto context = reinterpret_cast<ID3D11DeviceContext*>(renderer->data.context)) {
			videoPlayer.Update(context);
		}
	}
}

bool Manager::LoadNextVideo()
{
	if (videoPaths.empty()) {
		return false;
	}
	if (auto renderer = RE::BSGraphics::Renderer::GetSingleton()) {
		if (auto device = reinterpret_cast<ID3D11Device*>(renderer->data.forwarder)) {
			const std::uint32_t numVideos = static_cast<std::uint32_t>(videoPaths.size());

			if (selectedIndex >= numVideos) {
				std::random_device rd;
				std::mt19937       gen(rd());
				std::ranges::shuffle(videoPaths, gen);
				selectedIndex = 0;
			}

			videoPlayer.LoadVideo(device, videoPaths[selectedIndex].string(), playVideoAudio);
			selectedIndex++;
			return true;
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
		logger::error("Unable to find Data\\MainMenuVideo directory: {}", ec.message());
		return;
	}

	std::filesystem::directory_iterator iterator(directory, ec);
	if (ec) {
		logger::error("Unable to iterate over Data\\MainMenuVideo directory: {}", ec.message());
		return;
	}

	for (auto& entry : iterator) {
		if (entry.is_regular_file(ec) && !ec) {
			videoPaths.push_back({ entry.path().string() });
		}
	}

	std::random_device rd;
	std::mt19937       gen(rd());
	std::ranges::shuffle(videoPaths, gen);
}

EventResult Manager::ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*)
{
	if (!a_evn) {
		return EventResult::kContinue;
	}

	const auto& menuName = a_evn->menuName;

	if (menuName == RE::LoadingMenu::MENU_NAME) {
		if (a_evn->opening) {
			if (firstBoot) {
				firstBoot = false;
				timerRunning = true;
				timer.start();
				LoadNextVideo();
			} else if (mainMenuClosed) {
				if (videoPlayer.IsPlaying()) {
					videoPlayer.Reset();  // main menu -> loading screen -> game
				}
			}
		}
	} else if (menuName == RE::MainMenu::MENU_NAME) {
		mainMenuClosed = !a_evn->opening;
		if (a_evn->opening && timerRunning) {
			timer.stop();
			logger::info("Loading time: {}", timer.duration());
		}
	} else if (menuName == RE::FaderMenu::MENU_NAME) {
		if (a_evn->opening && RE::Main::GetSingleton()->resetGame) {
			if (playerDied && heyYouYoureFinallyAwake) {
				playerDied = false;
				return EventResult::kContinue;
			}
			LoadNextVideo();  // game -> quit to main menu
		}
	}

	return EventResult::kContinue;
}

EventResult Manager::ProcessEvent(const RE::TESDeathEvent* a_evn, RE::BSTEventSource<RE::TESDeathEvent>*)
{
	if (!a_evn || !a_evn->actorDying || !a_evn->actorDying->IsPlayerRef() || !a_evn->dead) {
		return EventResult::kContinue;
	}

	if (heyYouYoureFinallyAwake) {
		playerDied = true;
	}

	return EventResult::kContinue;
}
