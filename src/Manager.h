#pragma once

#include "VideoPlayer.h"

struct Key
{
	Key(std::int32_t a_key) :
		key(a_key),
		keyHeld(false)
	{}

	void LoadKeys(CSimpleIniA& a_ini, std::string_view a_setting, std::string_view a_comment);

	template <class F>
	void Process(F&& func)
	{
		if (key == -1) {
			return;
		}
		const bool isDown = (GetAsyncKeyState(key) & 0x8000) != 0;
		const bool justPressed = isDown && !keyHeld;
		keyHeld = isDown;
		if (justPressed) {
			func();
		}
	};

	std::int32_t key{ -1 };
	bool         keyHeld;
};

class Manager :
	public REX::Singleton<Manager>,
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

private:
	void ProcessInput();

	EventResult ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override;
	EventResult ProcessEvent(const RE::TESDeathEvent* a_evn, RE::BSTEventSource<RE::TESDeathEvent>*) override;

	// members
	VideoPlayer                        videoPlayer;
	std::vector<std::filesystem::path> videoPaths;
	std::uint32_t                      selectedIndex{ 0 };
	float                              chance{ 100.0f };
	Key                                stopPlayback{ VK_BACK };
	Key                                playNext{ VK_TAB };
	Key                                volumeUp{ VK_PRIOR };
	Key                                volumeDown{ VK_NEXT };
	float                              volumeStep{ 0.1f };
	bool                               firstBoot{ true };
	bool                               timerRunning{ false };
	bool                               mainMenuClosed{ false };
	bool                               heyYouYoureFinallyAwake{ false };
	bool                               playerDied{ false };
	bool                               showDebugInfo{ false };
	bool                               playVideoAudio{ true };
	Timer                              timer;
};
