#pragma once

namespace ImGui
{
	struct Texture
	{
		Texture() = default;
		Texture(ID3D11Device* device, std::uint32_t a_width, std::uint32_t a_height, float a_scale);
		~Texture() = default;

		void Update(ID3D11DeviceContext* context, const cv::Mat& frame) const;
		void SetDimensions(std::uint32_t a_width, std::uint32_t a_height, float a_scale);

		// members
		ImVec2                           size{ 0.0f, 0.0f };
		ComPtr<ID3D11Texture2D>          texture{ nullptr };
		ComPtr<ID3D11ShaderResourceView> srView{ nullptr };
		float                            scale{ 1.0f };
	};
}

enum class PLAYBACK_MODE
{
	kPlayOnce,
	kPlayNext,
	kLoop
};

class VideoPlayer
{
public:
	VideoPlayer() = default;
	~VideoPlayer()
	{
		if (resetting.exchange(true) == false) {
			ResetImpl();
		} else {
			if (resetThread.joinable()) {
				resetThread.request_stop();
				resetThread.join();
			}
		}
	}

	bool LoadVideo(ID3D11Device* device, const std::string& path, bool playAudio);
	void Update(ID3D11DeviceContext* context);
	void Reset(bool playNextVideo = false);

	ImTextureID GetTextureID() const;
	ImVec2      GetNativeSize() const;

	bool IsInitialized() const;
	bool IsPlaying() const;
	bool IsTransitioning() const;
	bool IsPlayingAudio() const;

	void ShowDebugInfo();

	PLAYBACK_MODE GetPlaybackMode() const;
	void          SetPlaybackMode(PLAYBACK_MODE a_mode);

private:
	void CreateVideoThread();
	void CreateAudioThread();
	void RestartAudioThread();

	bool LoadAudio(const std::string& path);

	void ResetAudio(bool playNextVideo = false);
	void ResetImpl(bool playNextVideo = false);

	using Lock = std::shared_mutex;
	using ReadLocker = std::scoped_lock<Lock>;
	using WriteLocker = std::unique_lock<Lock>;

	// members
	std::string                     currentVideo;
	cv::VideoCapture                cap;
	std::unique_ptr<ImGui::Texture> texture;
	PLAYBACK_MODE                   playbackMode{ PLAYBACK_MODE::kLoop };
	float                           targetFPS{ 30.0f };
	std::atomic<float>              actualFPS{ 0.0f };
	std::uint32_t                   frameCount{ 0 };
	float                           frameDuration{ 0.0f };
	std::atomic<std::uint32_t>      readFrameCount{ 0 };
	std::atomic<float>              elapsedTime{ 0.0f };
	cv::Mat                         videoFrame;
	mutable Lock                    videoFrameLock;
	ComPtr<IMFSourceReader>         audioReader{};
	ComPtr<IMFSinkWriter>           audioWriter{};
	ComPtr<IMFMediaSink>            mediaSink{};
	std::jthread                    audioThread;
	std::jthread                    videoThread;
	std::jthread                    resetThread;
	std::barrier<>                  startBarrier{ 2 };
	bool                            audioLoaded{ false };
	std::atomic<bool>               playing{ false };
	std::atomic<bool>               looping{ false };
	std::atomic<bool>               resetting{ false };
	std::atomic<bool>               transitioning{ false };
};
