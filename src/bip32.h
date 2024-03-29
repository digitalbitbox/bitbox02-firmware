// Copyright 2023 Shift Crypto AG
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

#ifndef _BIP32_H_
#define _BIP32_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <compiler_util.h>

USE_RESULT bool bip32_derive_xpub(
    const uint8_t* xpub78,
    const uint32_t* keypath,
    size_t keypath_len,
    uint8_t* xpub78_out);

#endif
