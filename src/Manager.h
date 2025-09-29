#pragma once

#include "VideoPlayer.h"

class Manager :
	public REX::Singleton<Manager>,
	public RE::BSTEventSink<RE::MenuOpenCloseEvent>
{
public:
	void Register();
	void LoadSettings();

	void Draw();
	void Update();

	void GetVideoList();
	bool LoadVideo();
	bool IsPlayingVideo() const;
	bool IsPlayingVideoAudio() const;

private:
	EventResult ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override;

	// members
	std::vector<std::filesystem::path> videoPaths;
	std::uint32_t                      selectedIndex{ 0 };
	VideoPlayer                        videoPlayer;
	bool                               firstBoot{ true };
	bool                               mainMenuClosed{ false };
	bool                               showBackground{ true };
	bool                               showDebugInfo{ false };
	bool                               playVideoAudio{ true };
	Timer                              timer;
};
