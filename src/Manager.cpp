#include "Manager.h"

#include "Hooks.h"
#include "ImGui/Renderer.h"
#include "ImGui/Util.h"

void Key::LoadKeys(CSimpleIniA& a_ini, std::string_view a_setting, std::string_view a_comment)
{
	key = ini::get_value(a_ini, key, "Hotkeys", std::format("{}Key", a_setting).c_str(), a_comment.data());
}

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

	SKSE::AllocTrampoline(42);
	ImGui::Renderer::Install();
	Hooks::Install();
}

void Manager::CompatibilityCheck()
{
	heyYouYoureFinallyAwake = GetModuleHandleA("po3_HeyYouYoureFinallyAwake.dll") != nullptr;
	logger::info("po3_HeyYoureFinallyAwake.dll installed : {}", heyYouYoureFinallyAwake);

	if (heyYouYoureFinallyAwake) {
		if (auto scriptEventHolder = RE::ScriptEventSourceHolder::GetSingleton()) {
			scriptEventHolder->AddEventSink<RE::TESDeathEvent>(this);
		}
	}
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

	ini::get_value(ini, chance, "Settings", "fPlaybackChance", ";Percentage chance that a video will play on startup");
	chance /= 100.0f;

	ini::get_value(ini, volumeStep, "Settings", "fVolumeStep", ";Volume change (0.1 = 10%)");

	stopPlayback.LoadKeys(ini, "iStopPlayback", ";https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes (-1 to disable)\n;Stop playback key (default: Backspace)");
	playNext.LoadKeys(ini, "iPlayNext", ";Next video key (default: Tab)");
	volumeUp.LoadKeys(ini, "iVolumeUp", ";Volume up key (default: PageUp)");
	volumeDown.LoadKeys(ini, "iVolumeDown", ";Volume down key (default:PageDown)");

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
		} else {
			videoPlayer.OnVolumeUpdate();
		}
	}
	ImGui::End();
}

void Manager::Update()
{
	if (!IsPlayingVideo()) {
		return;
	}

	ProcessInput();

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
	if (!std::filesystem::exists(directory, ec) || ec) {
		logger::error("Unable to find Data\\MainMenuVideo directory: {}", ec.message());
		return;
	}

	std::filesystem::directory_iterator iterator(directory, ec);
	if (ec) {
		logger::error("Unable to iterate over Data\\MainMenuVideo directory: {}", ec.message());
		return;
	}

	// https://gist.github.com/aaomidi/0a3b5c9bd563c9e012518b495410dc0e
	static constexpr std::array videoExtensions{
		".3g2"sv,
		".3gp"sv,
		".3gp2"sv,
		".3gpp"sv,
		".asf"sv,
		".avi"sv,
		".m4v"sv,
		".mov"sv,
		".mp4"sv,
		".wmv"sv,
		".amv"sv,
		".f4b"sv,
		".f4p"sv,
		".f4v"sv,
		".flv"sv,
		".gifv"sv,
		".m4p"sv,
		".mkv"sv,
		".mng"sv,
		".mod"sv,
		".mp2"sv,
		".mpe"sv,
		".mpeg"sv,
		".mpg"sv,
		".mpv"sv,
		".mxf"sv,
		".nsv"sv,
		".ogg"sv,
		".ogv"sv,
		".qt"sv,
		".rm"sv,
		".roq"sv,
		".rrc"sv,
		".svi"sv,
		".vob"sv,
		".webm"sv,
		".yuv"sv,
	};

	for (auto& entry : iterator) {
		if (!entry.is_regular_file(ec) || ec) {
			continue;
		}
		auto ext = clib_util::string::tolower(entry.path().extension().string());
		if (std::ranges::find(videoExtensions, ext) != videoExtensions.end()) {
			videoPaths.push_back({ entry.path().string() });
		} else {
			logger::warn("Skipping unsupported file: {}", entry.path().string());
		}
	}

	// first shuffle
	std::random_device rd;
	std::mt19937       gen(rd());
	std::ranges::shuffle(videoPaths, gen);
}

void Manager::ProcessInput()
{
	if (videoPlayer.IsTransitioning()) {
		return;
	}

	if (auto UI = RE::UI::GetSingleton(); UI && UI->IsMenuOpen(RE::Console::MENU_NAME)) {
		return;
	}

	stopPlayback.Process([this]() { videoPlayer.Reset(); });
	playNext.Process([this]() { videoPlayer.Reset(true); });
	volumeUp.Process([this]() { videoPlayer.IncrementVolume(volumeStep); });
	volumeDown.Process([this]() { videoPlayer.IncrementVolume(-volumeStep); });
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
				auto rng = clib_util::RNG().generate();
				if (rng > chance) {
					return EventResult::kContinue;
				}
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
			timerRunning = false;
			logger::info("Loading time: {}", timer.duration());
		}
	} else if (menuName == RE::FaderMenu::MENU_NAME) {
		if (a_evn->opening && RE::Main::GetSingleton()->resetGame) {
			if (playerDied && heyYouYoureFinallyAwake) {
				playerDied = false;
				return EventResult::kContinue;
			}
			auto rng = clib_util::RNG().generate();
			if (rng > chance) {
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

	playerDied = true;

	return EventResult::kContinue;
}
