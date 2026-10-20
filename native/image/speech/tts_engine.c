/* SPDX-License-Identifier: MIT
 * Fixed bounded rule-based renderer, linked with GPL-3.0-or-later eSpeak NG.
 * The distributed combined executable carries the upstream license/notices.
 */
#include "tts_engine.h"
#include <espeak-ng/speak_lib.h>
#include <string.h>

_Static_assert(sizeof(short) == sizeof(int16_t), "eSpeak requires signed 16-bit PCM");
static int16_t audio[LUMA_TTS_SAMPLES_MAX];
static size_t used;
static int started, overflowed, invalid_event, completed;

void luma_tts_forget(void) {
  volatile int16_t *cursor = audio;
  for (size_t i = 0; i < LUMA_TTS_SAMPLES_MAX; i++) cursor[i] = 0;
  used = 0;
}

static int valid_text(const unsigned char *text, size_t bytes) {
  if (!text || !bytes || bytes > LUMA_TTS_TEXT_MAX) return 0;
  size_t at = 0; int content = 0;
  while (at < bytes) {
    uint32_t scalar; size_t remaining;
    unsigned char first = text[at++];
    if (first < 128) { scalar = first; remaining = 0; }
    else if (first >= 0xc2 && first <= 0xdf) { scalar = first & 31u; remaining = 1; }
    else if (first >= 0xe0 && first <= 0xef) { scalar = first & 15u; remaining = 2; }
    else if (first >= 0xf0 && first <= 0xf4) { scalar = first & 7u; remaining = 3; }
    else return 0;
    if (remaining > bytes - at) return 0;
    for (size_t i = 0; i < remaining; i++) {
      unsigned char next = text[at++];
      if ((next & 0xc0u) != 0x80u) return 0;
      scalar = scalar * 64u + (next & 63u);
    }
    if ((remaining == 1 && scalar < 128) || (remaining == 2 && scalar < 2048) ||
        (remaining == 3 && scalar < 65536) || scalar > 0x10ffff ||
        (scalar >= 0xd800 && scalar <= 0xdfff) ||
        (scalar < 32 && scalar != 9 && scalar != 10) || (scalar >= 127 && scalar <= 159)) return 0;
    if (scalar != 9 && scalar != 10 && scalar != 32) content = 1;
  }
  return content;
}

static int collect(short *samples, int count, espeak_EVENT *events) {
  if (count < 0 || (count > 0 && !samples)) { invalid_event = 1; return 1; }
  if (events) {
    unsigned index = 0;
    while (index < 256 && events[index].type != espeakEVENT_LIST_TERMINATED) {
      if (events[index].type == espeakEVENT_PLAY ||
          (events[index].type == espeakEVENT_SAMPLERATE && events[index].id.number != (int)LUMA_TTS_RATE)) {
        invalid_event = 1; return 1;
      }
      index++;
    }
    if (index == 256) { invalid_event = 1; return 1; }
  }
  if ((size_t)count > LUMA_TTS_SAMPLES_MAX - used) { overflowed = 1; return 1; }
  if (count) { memcpy(audio + used, samples, (size_t)count * sizeof(int16_t)); used += (size_t)count; }
  if (!samples) completed = 1;
  return 0;
}

int luma_tts_render(const unsigned char *text, size_t bytes, const int16_t **samples, size_t *count) {
  if (!samples || !count) return LUMA_TTS_INPUT;
  *samples = NULL; *count = 0;
  if (started || !valid_text(text, bytes)) return LUMA_TTS_INPUT;
  started = 1;
  char literal[LUMA_TTS_TEXT_MAX + 1];
  memcpy(literal, text, bytes); literal[bytes] = 0;
  /* Explicit path disables home/config search. SYNCHRONOUS is retrieval-only,
   * not SYNCH_PLAYBACK; a separate consent-bound player owns actual output. */
  int rate = espeak_Initialize(AUDIO_OUTPUT_SYNCHRONOUS, 40,
                              "/usr/lib/x86_64-linux-gnu", espeakINITIALIZE_DONT_EXIT);
  if (rate != (int)LUMA_TTS_RATE) { memset(literal, 0, sizeof(literal)); return LUMA_TTS_ENGINE; }
  espeak_SetSynthCallback(collect);
  int result = LUMA_TTS_ENGINE;
  if (espeak_SetVoiceByName("en-us") == EE_OK &&
      espeak_SetParameter(espeakRATE, 175, 0) == EE_OK &&
      espeak_SetParameter(espeakVOLUME, 70, 0) == EE_OK &&
      espeak_SetParameter(espeakPITCH, 50, 0) == EE_OK &&
      espeak_SetParameter(espeakRANGE, 50, 0) == EE_OK) {
    espeak_ERROR rendered = espeak_Synth(literal, bytes + 1, 0, POS_CHARACTER, 0,
                                        espeakCHARS_UTF8 | espeakENDPAUSE, NULL, NULL);
    espeak_ERROR drained = espeak_Synchronize();
    if (overflowed) result = LUMA_TTS_LIMIT;
    else if (!invalid_event && completed && rendered == EE_OK && drained == EE_OK && used) result = LUMA_TTS_OK;
  }
  if (espeak_Terminate() != EE_OK) result = LUMA_TTS_ENGINE;
  memset(literal, 0, sizeof(literal));
  if (result != LUMA_TTS_OK) { luma_tts_forget(); return result; }
  *samples = audio; *count = used;
  return LUMA_TTS_OK;
}
