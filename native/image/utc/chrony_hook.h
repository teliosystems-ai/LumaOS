/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LUMA_CHRONY_HOOK_H
#define LUMA_CHRONY_HOOK_H
#include "ntp.h"
void LUH_Initialise(void);
void LUH_Finalise(void);
unsigned LUH_Register(const void *, const char *, int);
void LUH_Destroy(const void *, unsigned);
void LUH_Lose(unsigned);
void LUH_Leap(unsigned, int normal_leap);
void LUH_Good(unsigned, NTP_Sample *, int normal_leap);
#endif
