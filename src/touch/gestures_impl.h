// Copyright 2019 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __GESTURES_IMPL_H
#define __GESTURES_IMPL_H

/** Implementation-specific values for the gestures module. */

#ifndef TESTING

#include <platform/platform_config.h>
#if PLATFORM_BITBOX02 == 1
#include <qtouch_bitbox02.h>
#else
#include <qtouch_bitboxbase.h>
#endif

#define TOUCH_NUM_BUTTONS DEF_NUM_CHANNELS
#define TOUCH_NUM_SLIDERS DEF_NUM_SCROLLERS

#else

#define TOUCH_NUM_BUTTONS (8)
#define TOUCH_NUM_SLIDERS (2)

#endif

#endif // __GESTURES_IMPL_H
