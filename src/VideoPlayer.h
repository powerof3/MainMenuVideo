#pragma once

namespace ImGui
{
	struct Texture
	{
		Texture() = default;
		Texture(ID3D11Device* device, std::uint32_t a_width, std::uint32_t a_height, float a_scale);
		~Texture() = default;

		void Update(ID3D11DeviceContext* context, const cv::Mat& frame) const;

		// members
		ImVec2                           size{ 0.0f, 0.0f };
		ComPtr<ID3D11Texture2D>          texture{ nullptr };
		ComPtr<ID3D11ShaderResourceView> srView{ nullptr };
		float                            scale{ 1.0f };
	};
}

class VideoPlayer
{
public:
	VideoPlayer() = default;
	~VideoPlayer()
	{
		Reset();
	}

	bool LoadVideo(ID3D11Device* device, const std::string& path, bool playAudio);
	void Update(ID3D11DeviceContext* context, float deltaTime);
	void Reset();

	ImTextureID GetTextureID() const;
	ImVec2      GetNativeSize() const;

	bool IsInitialized() const;
	bool IsPlaying() const;
	bool IsPlayingAudio() const;

	void ShowDebugInfo();

private:
	void CreateVideoThread();
	void CreateAudioThread();
	
	bool LoadAudio(const std::string& path);
	void ResetAudio();

	using Lock = std::mutex;
	using Locker = std::scoped_lock<Lock>;

	cv::VideoCapture                cap;
	std::unique_ptr<ImGui::Texture> texture;
	float                           targetFPS{ 30.0f };
	float                           actualFPS{ 0.0f };
	std::uint32_t                   frameCount{ 0 };
	float                           frameDuration{ 0.0f };
	std::atomic<std::uint32_t>      grabbedFrameCount{ 0 };
	std::atomic<std::uint32_t>      retrievedFrameCount{ 0 };
	float                           elapsedTime{ 0.0f };
	std::atomic<float>              updateTimer{ 0.0f };
	std::jthread                    videoThread;
	cv::Mat                         videoFrame;
	ComPtr<IMFSourceReader>         audioReader{};
	ComPtr<IMFSinkWriter>           audioWriter{};
	ComPtr<IMFMediaSink>            mediaSink{};
	std::jthread                    audioThread;
	mutable Lock                    frameLock;
	bool                            audioLoaded{ false };
	std::atomic<bool>               playing{ false };
};
