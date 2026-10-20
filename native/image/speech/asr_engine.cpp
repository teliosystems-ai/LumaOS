/* SPDX-License-Identifier: MIT */
#include "asr_engine.h"
#include "whisper.h"
#include <algorithm>
#include <ctime>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>

namespace {
int64_t boot_ns() {
    struct timespec value {};
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0) return -1;
    return static_cast<int64_t>(value.tv_sec)*1000000000+value.tv_nsec;
}
struct operation {
    int64_t deadline;
    bool expired = false;
    std::size_t logged = 0;
};
struct model_input { int descriptor; off_t offset = 0; off_t size; bool failed = false; };
size_t read_model(void *opaque,void *destination,size_t requested) {
    auto *input=static_cast<model_input *>(opaque);
    if(!input->failed && input->offset==input->size)return 0;
    if(input->failed || requested > static_cast<size_t>(input->size-input->offset)) {
        input->failed=true;return 0;
    }
    const ssize_t received=pread(input->descriptor,destination,requested,input->offset);
    if(received != static_cast<ssize_t>(requested)) {input->failed=true;return 0;}
    input->offset+=received;return static_cast<size_t>(received);
}
bool model_eof(void *opaque) {
    auto *input=static_cast<model_input *>(opaque);
    return input->failed || input->offset==input->size;
}
void model_close(void *) {}
bool abort_decode(void *opaque) {
    auto *state = static_cast<operation *>(opaque);
    const auto now = boot_ns();
    state->expired = state->expired || now < 0 || now >= state->deadline;
    return state->expired;
}
void bounded_log(enum ggml_log_level, const char *text, void *opaque) {
    auto *state = static_cast<operation *>(opaque);
    if (!text || state->logged >= 8192) return;
    const std::size_t length = strnlen(text, 8192-state->logged);
    std::size_t offset = 0;
    while (offset < length) {
        const ssize_t count = write(2, text+offset, length-offset);
        if (count <= 0) break;
        offset += static_cast<std::size_t>(count);
    }
    state->logged += length;
}
bool literal_utf8(const std::string &value) {
    for (std::size_t index = 0; index < value.size();) {
        const auto first = static_cast<unsigned char>(value[index++]);
        if (first < 0x80) {
            if (first < 32 && first != '\n' && first != '\t') return false;
            if (first == 127) return false;
            continue;
        }
        int extra = first >= 0xc2 && first <= 0xdf ? 1 : first >= 0xe0 && first <= 0xef ? 2 : first >= 0xf0 && first <= 0xf4 ? 3 : -1;
        if (extra < 0 || index+static_cast<std::size_t>(extra) > value.size()) return false;
        uint32_t scalar = first & (extra == 1 ? 0x1f : extra == 2 ? 0x0f : 0x07);
        for (int n = 0; n < extra; n++) {
            auto next = static_cast<unsigned char>(value[index++]);
            if ((next & 0xc0) != 0x80) return false;
            scalar = (scalar << 6) | (next & 0x3f);
        }
        if ((extra == 1 && scalar < 0x80) || (extra == 2 && scalar < 0x800) ||
            (extra == 3 && scalar < 0x10000) || scalar > 0x10ffff ||
            (scalar >= 0xd800 && scalar <= 0xdfff) || (scalar >= 0x80 && scalar <= 0x9f)) return false;
    }
    return true;
}
}

bool luma_asr_transcribe(int model_fd, const int16_t *pcm, std::size_t samples,
                         luma_asr_result &output) {
    static bool used = false;
    output = {};
    struct stat model_info {};
    if (used || model_fd<0 || fstat(model_fd,&model_info) || !S_ISREG(model_info.st_mode) ||
        model_info.st_size != 77691713 || !pcm || samples < 1600 || samples > LUMA_ASR_SAMPLES) return false;
    bool nonzero = false;
    for (std::size_t i = 0; i < samples; i++) nonzero = nonzero || pcm[i] != 0;
    // Digital silence is not speech. Do not present the decoder's occasional
    // silence hallucination as a captured utterance, or substitute a transcript.
    if (!nonzero) return false;
    used = true;
    const auto start = boot_ns();
    if (start < 0) return false;
    operation state {start+18LL*1000000000, false, 0};
    whisper_log_set(bounded_log, &state);
    auto context_parameters = whisper_context_default_params();
    context_parameters.use_gpu = false;
    context_parameters.flash_attn = false;
    model_input input {model_fd,0,model_info.st_size,false};
    whisper_model_loader loader {&input,read_model,model_eof,model_close};
    auto *context = whisper_init_with_params(&loader, context_parameters);
    if (!context || input.failed || input.offset != input.size) {
        if(context)whisper_free(context);
        whisper_log_set(nullptr,nullptr);return false;
    }
    std::vector<float> audio(samples);
    for (std::size_t i = 0; i < samples; i++) audio[i] = static_cast<float>(pcm[i])/32768.0f;
    auto parameters = whisper_full_default_params(WHISPER_SAMPLING_GREEDY);
    parameters.n_threads = 2;
    parameters.n_max_text_ctx = 0;
    parameters.offset_ms = 0;
    parameters.duration_ms = 0;
    parameters.translate = false;
    parameters.no_context = true;
    parameters.no_timestamps = true;
    parameters.single_segment = true;
    parameters.print_special = false;
    parameters.print_progress = false;
    parameters.print_realtime = false;
    parameters.print_timestamps = false;
    parameters.token_timestamps = false;
    parameters.max_len = 0;
    parameters.split_on_word = false;
    parameters.max_tokens = LUMA_ASR_DECODER_TOKENS;
    parameters.language = "en";
    parameters.detect_language = false;
    parameters.suppress_blank = true;
    parameters.suppress_nst = true;
    parameters.temperature = 0.0f;
    parameters.temperature_inc = 0.0f;
    parameters.greedy.best_of = 1;
    parameters.beam_search.beam_size = 1;
    parameters.initial_prompt = nullptr;
    parameters.prompt_tokens = nullptr;
    parameters.prompt_n_tokens = 0;
    parameters.carry_initial_prompt = false;
    parameters.vad = false;
    parameters.abort_callback = abort_decode;
    parameters.abort_callback_user_data = &state;
    const int status = abort_decode(&state) ? -1 : whisper_full(context, parameters, audio.data(), static_cast<int>(samples));
    bool accepted = status == 0 && !abort_decode(&state);
    const int segments = accepted ? whisper_full_n_segments(context) : 0;
    if (segments < 0 || segments > 1) accepted = false;
    for (int i = 0; accepted && i < segments; i++) {
        const int count = whisper_full_n_tokens(context, i);
        const char *text = whisper_full_get_segment_text(context, i);
        // A decoder hitting its exact limit cannot prove that the utterance
        // completed. Do not publish a plausible truncated transcript as success.
        if (count < 0 || count >= LUMA_ASR_DECODER_TOKENS || !text ||
            output.decoder_tokens+count >= LUMA_ASR_DECODER_TOKENS) { accepted = false; break; }
        const auto length = strnlen(text, LUMA_ASR_TEXT+1);
        if (length > LUMA_ASR_TEXT-output.text.size()) { accepted = false; break; }
        output.text.append(text, length);
        output.decoder_tokens += count;
    }
    accepted = accepted && literal_utf8(output.text);
    std::fill(audio.begin(), audio.end(), 0.0f);
    whisper_free(context);
    whisper_log_set(nullptr, nullptr);
    if (!accepted) { output = {}; return false; }
    output.audio_samples = static_cast<int64_t>(samples);
    return true;
}
