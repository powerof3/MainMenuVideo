#pragma once

#include "VideoPlayer.h"

struct Key
{
	Key(std::string_view a_key, std::int32_t a_default) :
		key("Hotkeys", a_key, a_default)
	{}

	Key(const Key&) = delete;
	Key(Key&&) = delete;
	Key& operator=(const Key&) = delete;
	Key& operator=(Key&&) = delete;

	template <class F>
	void Process(F&& func)
	{
		const auto vk = key.GetValue();
		if (vk == -1) {
			return;
		}

		const bool isDown = (GetAsyncKeyState(vk) & 0x8000) != 0;
		const bool justPressed = isDown && !keyHeld;
		keyHeld = isDown;

		if (justPressed) {
			func();
		}
	}

	REX::TIniSetting<std::int32_t> key;
	bool                           keyHeld{ false };
};

class Manager :
	public REX::TSingleton<Manager>,
	public RE::BSTEventSink<RE::MenuOpenCloseEvent>,
	public RE::BSTEventSink<RE::TESDeathEvent>
{
public:
	void Register();
	void CompatibilityCheck();
	void LoadSettings();

	void Draw();
	void Update();

	void GetVideoList();

	bool LoadNextVideo();

	bool IsPlayingVideo() const;
	bool IsPlayingVideoAudio() const;

	[[nodiscard]] float GetPlaybackChance() const { return chance.GetValue() / 100.0f; }

private:
	void ProcessInput();

	EventResult ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override;
	EventResult ProcessEvent(const RE::TESDeathEvent* a_evn, RE::BSTEventSource<RE::TESDeathEvent>*) override;

	// members
	static constexpr auto path = R"(Data\SKSE\Plugins\po3_MainMenuVideo.ini)"sv;

	VideoPlayer                        videoPlayer;
	std::vector<std::filesystem::path> videoPaths;
	std::uint32_t                      selectedIndex{ 0 };

	REX::TIniSetting<std::uint32_t> playbackMode{ "Settings", "iPlaybackMode", std::to_underlying(PLAYBACK_MODE::kLoop) };
	REX::TIniSetting<std::uint32_t> scalingMode{ "Settings", "iScalingMode", std::to_underlying(SCALING_MODE::kFit) };
	REX::TIniSetting<bool>          playVideoAudio{ "Settings", "bPlayAudio", true };
	REX::TIniSetting<bool>          showDebugInfo{ "Settings", "bDebugStats", false };
	REX::TIniSetting<float>         chance{ "Settings", "fPlaybackChance", 100.0f };
	REX::TIniSetting<float>         volumeStep{ "Settings", "fVolumeStep", 0.1f };

	Key stopPlayback{ "iStopPlaybackKey"sv, VK_BACK };
	Key playNext{ "iPlayNextKey"sv, VK_TAB };
	Key volumeUp{ "iVolumeUpKey"sv, VK_PRIOR };
	Key volumeDown{ "iVolumeDownKey"sv, VK_NEXT };

	bool                firstBoot{ true };
	bool                timerRunning{ false };
	bool                mainMenuClosed{ false };
	bool                heyYouYoureFinallyAwake{ false };
	bool                playerDied{ false };
	REX::FTimer         timer;
	REX::TRandom<float> rng{};
};
