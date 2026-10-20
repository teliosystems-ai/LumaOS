/* SPDX-License-Identifier: MIT */
#ifndef LUMA_ASR_ENGINE_H
#define LUMA_ASR_ENGINE_H
#include <cstddef>
#include <cstdint>
#include <string>

constexpr std::size_t LUMA_ASR_SAMPLES = 16000 * 30;
constexpr std::size_t LUMA_ASR_TEXT = 8192;
constexpr int LUMA_ASR_DECODER_TOKENS = 128;
struct luma_asr_result {
    std::string text;
    int decoder_tokens = 0;
    int64_t audio_samples = 0;
};
/* One explicit offline English transcription. The caller retains the exact
 * immutable model descriptor and all grant/resource/revocation authority.
 * No microphone, network, translation or consequential action is opened. */
bool luma_asr_transcribe(int model_fd, const int16_t *pcm, std::size_t samples,
                         luma_asr_result &output);
#endif
