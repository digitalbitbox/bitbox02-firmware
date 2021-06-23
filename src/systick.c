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

#include "stdint.h"

#include "systick.h"

static volatile uint32_t systick;

#ifdef TESTING
void SysTick_Handler(void);
#else
#include <driver_init.h>
#endif

// Get's called every clock tick (1ms)
void SysTick_Handler(void)
{
    systick++;
}

uint32_t systick_get(void)
{
    return systick;
}
