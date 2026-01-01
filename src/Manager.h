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

	bool LoadRandomVideo();
	bool LoadNextVideo();

	bool IsPlayingVideo() const;
	bool IsPlayingVideoAudio() const;

private:
	bool LoadRandomVideo(ID3D11Device* a_device, std::size_t numVideos);

	EventResult ProcessEvent(const RE::MenuOpenCloseEvent* a_evn, RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override;

	// members
	std::vector<std::filesystem::path> videoPaths;
	std::size_t                        selectedIndex{ 0 };
	VideoPlayer                        videoPlayer;
	bool                               firstBoot{ true };
	bool                               mainMenuClosed{ false };
	bool                               showDebugInfo{ false };
	bool                               playVideoAudio{ true };
	Timer                              timer;
};
