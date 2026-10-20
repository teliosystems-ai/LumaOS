/* SPDX-License-Identifier: MIT */
#ifndef LUMA_TTS_ENGINE_H
#define LUMA_TTS_ENGINE_H
#include <stddef.h>
#include <stdint.h>
#define LUMA_TTS_RATE 22050u
#define LUMA_TTS_SECONDS 30u
#define LUMA_TTS_TEXT_MAX 4096u
#define LUMA_TTS_SAMPLES_MAX (LUMA_TTS_RATE * LUMA_TTS_SECONDS)
enum luma_tts_status { LUMA_TTS_OK = 0, LUMA_TTS_INPUT = 1, LUMA_TTS_LIMIT = 2, LUMA_TTS_ENGINE = 3 };
/* One invocation per owned worker. No audio device is opened by this engine.
 * Text is literal UTF-8, never SSML/phoneme markup or a filename/command. */
int luma_tts_render(const unsigned char *text, size_t bytes, const int16_t **samples, size_t *count);
void luma_tts_forget(void);
#endif
