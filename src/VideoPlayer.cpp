#include "VideoPlayer.h"

#include "Manager.h"

ImGui::Texture::Texture(ID3D11Device* device, std::uint32_t a_width, std::uint32_t a_height, float a_scale) :
	size(static_cast<float>(a_width), static_cast<float>(a_height)),
	scale(a_scale)
{
	D3D11_TEXTURE2D_DESC desc{
		.Width = a_width,
		.Height = a_height,
		.MipLevels = 1,
		.ArraySize = 1,
		.Format = DXGI_FORMAT_B8G8R8A8_UNORM,
		.SampleDesc = { 1, 0 },
		.Usage = D3D11_USAGE_DYNAMIC,
		.BindFlags = D3D11_BIND_SHADER_RESOURCE,
		.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE,
		.MiscFlags = 0
	};

	if (FAILED(device->CreateTexture2D(&desc, nullptr, &texture)) ||
		FAILED(device->CreateShaderResourceView(texture.Get(), nullptr, &srView))) {
		texture.Reset();
		srView.Reset();
		return;
	}
}

void ImGui::Texture::Update(ID3D11DeviceContext* context, const cv::Mat& mat) const
{
	D3D11_MAPPED_SUBRESOURCE mapped{};
	if (SUCCEEDED(context->Map(texture.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped))) {
		constexpr std::uint32_t bytesPerPixel = 4;  // BGRA
		const auto              srcRowBytes = mat.cols * bytesPerPixel;

		if (mapped.RowPitch == srcRowBytes) {
			std::memcpy(mapped.pData, mat.data, mat.rows * srcRowBytes);
		} else {
			auto* dst = static_cast<std::uint8_t*>(mapped.pData);
			for (std::int32_t y = 0; y < mat.rows; ++y) {
				std::memcpy(dst + y * mapped.RowPitch, mat.ptr<uchar>(y), srcRowBytes);
			}
		}
		context->Unmap(texture.Get(), 0);
	}
}

void ImGui::Texture::SetDimensions(std::uint32_t a_width, std::uint32_t a_height, float a_scale)
{
	size = ImVec2(static_cast<float>(a_width), static_cast<float>(a_height));
	scale = a_scale;
}

// https://stackoverflow.com/a/54946067
// convert video to use MF? later
bool VideoPlayer::LoadAudio(const std::string& path)
{
	HRESULT hr = MFCreateSourceReaderFromURL(stl::utf8_to_utf16(path)->c_str(), nullptr, &audioReader);
	if (SUCCEEDED(hr)) {  // Select only the audio stream
		hr = audioReader->SetStreamSelection((DWORD)MF_SOURCE_READER_ALL_STREAMS, FALSE);
		if (SUCCEEDED(hr)) {
			hr = audioReader->SetStreamSelection((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, TRUE);
			if (SUCCEEDED(hr)) {
				hr = MFCreateAudioRenderer(nullptr, &mediaSink);
				if (SUCCEEDED(hr)) {
					ComPtr<IMFStreamSink> streamSink;
					hr = mediaSink->GetStreamSinkByIndex(0, &streamSink);
					if (SUCCEEDED(hr)) {
						ComPtr<IMFMediaTypeHandler> typeHandler;
						hr = streamSink->GetMediaTypeHandler(&typeHandler);
						if (SUCCEEDED(hr)) {
							DWORD                dwCount = 0;
							ComPtr<IMFMediaType> inputType;
							hr = typeHandler->GetMediaTypeCount(&dwCount);
							if (SUCCEEDED(hr)) {
								bool mediaTypeSupported = false;
								for (DWORD i = 0; i < dwCount; i++) {
									inputType = nullptr;
									typeHandler->GetMediaTypeByIndex(i, &inputType);
									if (SUCCEEDED(typeHandler->IsMediaTypeSupported(inputType.Get(), NULL))) {
										mediaTypeSupported = true;
										break;
									}
								}
								if (mediaTypeSupported) {
									hr = audioReader->SetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, NULL, inputType.Get());
									if (SUCCEEDED(hr)) {
										hr = typeHandler->SetCurrentMediaType(inputType.Get());
										ComPtr<IMFAttributes> sinkWriterAttributes;
										hr = MFCreateAttributes(&sinkWriterAttributes, 1);
										if (SUCCEEDED(hr)) {
											hr = sinkWriterAttributes->SetUINT32(MF_READWRITE_ENABLE_HARDWARE_TRANSFORMS, 1);
											if (SUCCEEDED(hr)) {
												hr = MFCreateSinkWriterFromMediaSink(mediaSink.Get(), nullptr, &audioWriter);
												if (SUCCEEDED(hr)) {
													hr = audioWriter->SetInputMediaType(0, inputType.Get(), nullptr);
													if (SUCCEEDED(hr)) {
														return true;
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ResetAudio();

	return false;
}

void VideoPlayer::CreateVideoThread()
{
	if (!videoThread.joinable()) {
		videoThread = std::jthread([this](std::stop_token st) {
			if (audioLoaded) {
				startBarrier.arrive_and_wait();  // wait until both video+audio are ready
			}
			transitioning.store(false);
			playing.store(true);

			using clock = std::chrono::steady_clock;
			using duration = std::chrono::duration<double>;
			using time_point = std::chrono::time_point<clock, duration>;

			const auto frameDuration = duration(1.0 / targetFPS);
			const auto debugUpdateInterval = duration(0.1);  // 0.1s

			time_point frameStartTime = clock::now();
			time_point playbackStart = frameStartTime;
			time_point debugUpdateInfoTime = frameStartTime;

			cv::Mat frame;
			cv::Mat processedFrame;
			bool    started = true;

			auto on_video_end = [&]() {
				switch (playbackMode) {
				case PLAYBACK_MODE::kPlayOnce:
					Reset();
					break;
				case PLAYBACK_MODE::kPlayNext:
					Reset(true);
					break;
				case PLAYBACK_MODE::kLoop:
					{
						readFrameCount.store(0);
						cap.release();
						cap.open(currentVideo);
						RestartAudioThread();
						if (audioLoaded) {
							startBarrier.arrive_and_wait();
						}
						// Reset timing for new loop
						frameStartTime = clock::now();
						playbackStart = frameStartTime;
						debugUpdateInfoTime = frameStartTime;
						started = true;
					}
					break;
				default:
					std::unreachable();
				}
			};

			while (!st.stop_requested()) {
				const auto now = clock::now();
				const auto elapsed = now - frameStartTime;

				if (!started && elapsed < frameDuration) {
					const auto sleepDuration = frameDuration - elapsed;
					if (sleepDuration > std::chrono::milliseconds(0)) {
						std::this_thread::sleep_for(sleepDuration);
					}
					continue;
				}

				started = false;

				if (cap.read(frame) && !frame.empty()) {
					if (frame.channels() == 3) {
						cv::cvtColor(frame, processedFrame, cv::COLOR_BGR2BGRA);
					} else if (frame.channels() == 4) {
						processedFrame = frame.clone();
					} else {
						frameStartTime += frameDuration;
						continue;
					}
					if (texture->scale != 1.0f) {
						cv::resize(processedFrame, processedFrame, cv::Size(), texture->scale, texture->scale, texture->scale > 1.0f ? cv::INTER_CUBIC : cv::INTER_AREA);
					}
					{
						WriteLocker lock(videoFrameLock);
						videoFrame = std::move(processedFrame);
					}
					readFrameCount.fetch_add(1, std::memory_order_relaxed);
				} else {
					on_video_end();
					continue;
				}

				started = false;
				frameStartTime += frameDuration;

				if (now - frameStartTime > frameDuration * 2) {
					const auto expectedElapsed = readFrameCount.load(std::memory_order_relaxed) * frameDuration;
					frameStartTime = playbackStart + expectedElapsed;
				}

				if (now - debugUpdateInfoTime >= debugUpdateInterval) {
					const auto totalElapsed = duration(now - playbackStart).count();
					const auto frameCount = readFrameCount.load(std::memory_order_relaxed);
					elapsedTime = static_cast<float>(totalElapsed);
					actualFPS = static_cast<float>(frameCount / totalElapsed);
					debugUpdateInfoTime = now;
				}
			}
		});
	}
}

void VideoPlayer::Update(ID3D11DeviceContext* context)
{
	cv::Mat frameCopy;
	{
		ReadLocker lock(videoFrameLock);
		if (!videoFrame.empty()) {
			frameCopy = videoFrame.clone();
		}
	}

	if (!frameCopy.empty() && texture) {
		texture->Update(context, frameCopy);
	}
}

void VideoPlayer::CreateAudioThread()
{
	if (audioLoaded && !audioThread.joinable()) {
		audioThread = std::jthread([this](std::stop_token st) {
			if (!looping.load()) {
				startBarrier.arrive_and_wait();
			}
			audioWriter->BeginWriting();

			while (!st.stop_requested()) {
				ComPtr<IMFSample> sample;
				DWORD             streamFlags = 0;
				MFTIME            timestamp = 0;

				HRESULT hr = audioReader->ReadSample((DWORD)MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0, nullptr, &streamFlags, &timestamp, &sample);
				if (FAILED(hr)) {
					break;
				}

				if (streamFlags & MF_SOURCE_READERF_ENDOFSTREAM) {
					continue;
				}

				if (streamFlags & MF_SOURCE_READERF_STREAMTICK) {
					audioWriter->SendStreamTick(0, timestamp);
				}

				if (sample) {
					audioWriter->WriteSample(0, sample.Get());
				}
			}
		});
	}
}

void VideoPlayer::RestartAudioThread()
{
	if (audioLoaded) {
		audioThread = {};
		ResetAudio();
		audioLoaded = LoadAudio(currentVideo);
		CreateAudioThread();
	}
}

bool VideoPlayer::LoadVideo(ID3D11Device* device, const std::string& path, bool playAudio)
{
	static std::vector<std::int32_t> params{
		cv::CAP_PROP_HW_ACCELERATION,
		cv::VIDEO_ACCELERATION_D3D11
	};

	cap.open(path, cv::CAP_MSMF, params);
	if (!cap.isOpened()) {
		logger::warn("Couldn't load {}", path);
		return false;
	}

	currentVideo = path;

	auto videoWidth = static_cast<std::uint32_t>(cap.get(cv::CAP_PROP_FRAME_WIDTH));
	auto videoHeight = static_cast<std::uint32_t>(cap.get(cv::CAP_PROP_FRAME_HEIGHT));
	frameCount = static_cast<std::uint32_t>(cap.get(cv::CAP_PROP_FRAME_COUNT));
	targetFPS = static_cast<float>(cap.get(cv::CAP_PROP_FPS));
	frameDuration = targetFPS > 0.0f ? (1.0f / targetFPS) : 0.033f;

	logger::info("Loading {} ({}x{}|{} FPS|{} frames)", path, videoWidth, videoHeight, targetFPS, frameCount);

	auto scale = 1.0f;
	if (auto gameWidth = RE::BSGraphics::Renderer::GetScreenSize().width; gameWidth != videoWidth) {
		scale = static_cast<float>(gameWidth) / videoWidth;
		auto newVideoHeight = static_cast<std::uint32_t>(videoHeight * scale);
		logger::info("\tScaling to fit game resolution({}x{}->{}x{} ({}X))", videoWidth, videoHeight, gameWidth, newVideoHeight, scale);
		videoWidth = gameWidth;
		videoHeight = newVideoHeight;
	}

	if (!texture) {
		texture = std::make_unique<ImGui::Texture>(device, videoWidth, videoHeight, scale);
		if (!texture || !texture->texture || !texture->srView) {
			cap.release();
			return false;
		}
	} else {
		texture->SetDimensions(videoWidth, videoHeight, scale);
	}

	audioLoaded = playAudio ? LoadAudio(path) : false;

	CreateAudioThread();
	CreateVideoThread();

	return true;
}

void VideoPlayer::ResetAudio(bool playNextVideo)
{
	audioReader = nullptr;
	if (audioWriter) {
		if (!playNextVideo) {
			audioWriter->Flush(0);
		}
		audioWriter->Finalize();
		audioWriter = nullptr;
	}
	if (mediaSink) {
		mediaSink->Shutdown();
		mediaSink = nullptr;
	}
}

void VideoPlayer::ResetImpl(bool playNextVideo)
{
	looping.store(false);
	playing.store(false);

	if (videoThread.joinable()) {
		videoThread.request_stop();
		videoThread.join();
	}
	if (audioThread.joinable()) {
		audioThread.request_stop();
		audioThread.join();
	}

	readFrameCount.store(0);
	elapsedTime.store(0);

	{
		WriteLocker lock(videoFrameLock);
		videoFrame.release();
	}

	if (audioLoaded) {
		ResetAudio(playNextVideo);
		if (!playNextVideo) {
			audioLoaded = false;
		}
	}

	if (!playNextVideo) {
		texture.reset();
	}
	cap.release();

	if (playNextVideo && !Manager::GetSingleton()->LoadNextVideo()) {
		transitioning.store(false);
	}

	resetting.store(false);
}

void VideoPlayer::Reset(bool playNextVideo)
{
	if (!IsPlaying() || resetting.exchange(true)) {
		return;
	}

	if (playNextVideo) {
		transitioning.store(true);
	}

	resetThread = std::jthread([this, playNextVideo](std::stop_token) {
		ResetImpl(playNextVideo);
	});
	resetThread.detach();
}

ImTextureID VideoPlayer::GetTextureID() const
{
	return texture ? (ImTextureID)texture->srView.Get() : 0;
}

ImVec2 VideoPlayer::GetNativeSize() const
{
	return texture ? texture->size : ImGui::GetIO().DisplaySize;
}

bool VideoPlayer::IsInitialized() const
{
	return texture && texture->srView;
}

bool VideoPlayer::IsPlaying() const
{
	return (playing.load() && !resetting.load()) || IsTransitioning();
}

bool VideoPlayer::IsTransitioning() const
{
	return transitioning.load();
}

bool VideoPlayer::IsPlayingAudio() const
{
	return IsPlaying() && audioLoaded;
}

void VideoPlayer::ShowDebugInfo()
{
	auto min = ImGui::GetItemRectMin();
	ImGui::SetCursorScreenPos(min);

	if (IsTransitioning()) {
		ImGui::Text("TRANSITIONING");
		return;
	}

	ImGui::Text("%s", currentVideo.c_str());
	ImGui::Text("\tElapsed Time: %.1f seconds", elapsedTime.load());
	ImGui::Text("\tFrames Processed: %u/%u", readFrameCount.load(), frameCount);
	ImGui::Text("\tTarget FPS: %.1f", targetFPS);
	ImGui::Text("\tActual FPS: %.1f", actualFPS.load());
}

PLAYBACK_MODE VideoPlayer::GetPlaybackMode() const
{
	return playbackMode;
}

void VideoPlayer::SetPlaybackMode(PLAYBACK_MODE a_mode)
{
	playbackMode = a_mode;
}
