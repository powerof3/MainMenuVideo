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

			auto  startTime = std::chrono::steady_clock::now();
			auto  lastDebugTime = startTime;
			float localTimer = 0.0f;
			bool  justReset = true;

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

						startTime = std::chrono::steady_clock::now();
						lastDebugTime = startTime;
						localTimer = 0.0f;
						looping.store(true);
						justReset = true;

						RestartAudioThread();
					}
					break;
				default:
					std::unreachable();
				}
			};

			while (!st.stop_requested()) {
				float dt = updateTimer.exchange(0.0f, std::memory_order_acq_rel);
				localTimer += dt;

				if (!justReset) {
					if (localTimer < frameDuration) {
						auto sleepTime = frameDuration - localTimer;
						if (sleepTime > 0.0f) {
							std::this_thread::sleep_for(std::chrono::duration<float>(sleepTime));
						}
						continue;
					}
				}
				justReset = false;

				localTimer -= frameDuration;

				if (localTimer > 5.0f * frameDuration) {
					localTimer = 0.0f;
				}

				cv::Mat frame;
				if (cap.read(frame) && !frame.empty()) {
					cv::Mat processedFrame;
					if (frame.channels() == 3) {
						cv::cvtColor(frame, processedFrame, cv::COLOR_BGR2BGRA);
					} else if (frame.channels() == 4) {
						processedFrame = frame.clone();
					} else {
						continue;
					}
					if (texture->scale != 1.0f) {
						cv::resize(processedFrame, processedFrame, cv::Size(), texture->scale, texture->scale, texture->scale > 1.0f ? cv::INTER_CUBIC : cv::INTER_AREA);
					}
					{
						Locker lock(frameLock);
						videoFrame = std::move(processedFrame);
					}
					readFrameCount++;
				} else {
					on_video_end();
				}

				auto now = std::chrono::steady_clock::now();
				if (std::chrono::duration<float>(now - lastDebugTime).count() >= 0.1f) {
					float totalElapsed = std::chrono::duration<float>(now - startTime).count();
					elapsedTime = totalElapsed;
					actualFPS = readFrameCount.load() / totalElapsed;
					lastDebugTime = now;
				}
			}
		});
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

void VideoPlayer::Update(ID3D11DeviceContext* context, float deltaTime)
{
	updateTimer.fetch_add(deltaTime, std::memory_order_relaxed);

	cv::Mat frameCopy;
	{
		Locker lock(frameLock);
		if (!videoFrame.empty()) {
			frameCopy = videoFrame.clone();
		}
	}

	if (!frameCopy.empty() && texture) {
		texture->Update(context, frameCopy);
	}
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
	videoThread = {};
	readFrameCount = 0;
	elapsedTime = 0.0f;
	updateTimer = 0.0f;
	
	{
		Locker lock(frameLock);
		videoFrame.release();
	}

	audioThread = {};
	if (audioLoaded) {
		ResetAudio(playNextVideo);
		audioLoaded = false;
	}

	if (!playNextVideo) {
		texture.reset();
	}
	cap.release();

	looping.store(false);
	resetting.store(false);
	playing.store(false);

	if (playNextVideo) {
		if (!Manager::GetSingleton()->LoadNextVideo()) {
			transitioning.store(false);
		}
	}
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
	if (IsTransitioning()) {
		ImGui::Text("TRANSITIONING");
		return;
	}

	auto min = ImGui::GetItemRectMin();
	ImGui::SetCursorScreenPos(min);

	ImGui::Text("%s", currentVideo.c_str());
	ImGui::Text("\tElapsed Time: %.1f seconds", elapsedTime);
	ImGui::Text("\tFrames Processed: %u/%u", readFrameCount.load(), frameCount);
	ImGui::Text("\tTarget FPS: %.1f", targetFPS);
	ImGui::Text("\tActual FPS: %.1f", actualFPS);
}

PLAYBACK_MODE VideoPlayer::GetPlaybackMode() const
{
	return playbackMode;
}

void VideoPlayer::SetPlaybackMode(PLAYBACK_MODE a_mode)
{
	playbackMode = a_mode;
}
