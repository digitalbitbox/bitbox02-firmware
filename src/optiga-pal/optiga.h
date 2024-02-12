// Copyright 2024 Shift Crypto AG
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

#ifndef _OPTIGA_H_
#define _OPTIGA_H_
#include "securechip/securechip.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int optiga_setup(const securechip_interface_functions_t* ifs);
bool optiga_random(uint8_t* rand_out);
int optiga_hmac(const uint8_t* msg, size_t len, uint8_t* mac_out);
bool optiga_model(securechip_model_t* model_out);
#endif // _OPTIGA_H_
