#pragma once

#include "VideoPlayer.h"

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
	EventResult ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override;
	EventResult ProcessEvent(const RE::TESDeathEvent* a_evn, RE::BSTEventSource<RE::TESDeathEvent>*) override;

	// members
	std::vector<std::filesystem::path> videoPaths;
	std::uint32_t                      selectedIndex{ 0 };
	VideoPlayer                        videoPlayer;
	bool                               firstBoot{ true };
	bool                               timerRunning{ false };
	bool                               mainMenuClosed{ false };
	bool                               heyYouYoureFinallyAwake{ false };
	bool                               playerDied{ false };
	bool                               showDebugInfo{ false };
	bool                               playVideoAudio{ true };
	Timer                              timer;
};
