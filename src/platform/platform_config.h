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

#ifndef _PLATFORM_CONFIG_H
#define _PLATFORM_CONFIG_H

#if !defined(PLATFORM_BITBOX02)
#define PLATFORM_BITBOX02 0
#elif PLATFORM_BITBOX02 != 0 && PLATFORM_BITBOX02 != 1
#error "Invalid value for PLATFORM_BITBOX02."
#endif

#if !defined(PLATFORM_BITBOXBASE)
#define PLATFORM_BITBOXBASE 0
#elif PLATFORM_BITBOXBASE != 0 && PLATFORM_BITBOXBASE != 1
#error "Invalid value for PLATFORM_BITBOXBASE."
#endif

#if !defined(EDITION_STANDARD)
#define EDITION_STANDARD 0
#elif EDITION_STANDARD != 0 && EDITION_STANDARD != 1
#error "Invalid value for EDITION_STANDARD."
#endif
#if !defined(EDITION_BTCONLY)
#define EDITION_BTCONLY 0
#elif EDITION_BTCONLY != 0 && EDITION_BTCONLY != 1
#error "Invalid value for EDITION_BTCONLY."
#endif
#if !defined(EDITION_FACTORYSETUP)
#define EDITION_FACTORYSETUP 0
#elif EDITION_FACTORYSETUP != 0 && EDITION_FACTORYSETUP != 1
#error "Invalid value for EDITION_FACTORYSETUP."
#endif

#if PLATFORM_BITBOX02 == 1

#if EDITION_STANDARD == 1
#define PRODUCT_BITBOX_MULTI 1
#elif EDITION_BTCONLY == 1
#define PRODUCT_BITBOX_BTCONLY 1
#elif EDITION_FACTORYSETUP == 1
#define PRODUCT_BITBOX02_FACTORYSETUP 1
#else
#error "Invalid EDITION value."
#endif

#elif PLATFORM_BITBOXBASE == 1

#if EDITION_STANDARD == 1
#define PRODUCT_BITBOX_BASE 1
#elif EDITION_FACTORYSETUP == 1
#define PRODUCT_BITBOXBASE_FACTORYSETUP 1
#else
#error "Invalid EDITION value."
#endif

#else
#error "Invalid PRODUCT value."
#endif

#if !defined(PRODUCT_BITBOX_MULTI)
#define PRODUCT_BITBOX_MULTI 0
#elif PRODUCT_BITBOX_MULTI != 1
#error "invalid PRODUCT_BITBOX_MULTI value"
#endif

#if !defined(PRODUCT_BITBOX_BTCONLY)
#define PRODUCT_BITBOX_BTCONLY 0
#elif PRODUCT_BITBOX_BTCONLY != 1
#error "invalid PRODUCT_BITBOX_BTCONLY value"
#endif

#if !defined(PRODUCT_BITBOX_BASE)
#define PRODUCT_BITBOX_BASE 0
#elif PRODUCT_BITBOX_BASE != 1
#error "invalid PRODUCT_BITBOX_BASE value"
#endif

#if !defined(PRODUCT_BITBOX02_FACTORYSETUP)
#define PRODUCT_BITBOX02_FACTORYSETUP 0
#elif PRODUCT_BITBOX02_FACTORYSETUP != 1
#error "invald PRODUCT_BITBOX02_FACTORYSETUP value"
#endif
#if !defined(PRODUCT_BITBOXBASE_FACTORYSETUP)
#define PRODUCT_BITBOXBASE_FACTORYSETUP 0
#elif PRODUCT_BITBOXBASE_FACTORYSETUP != 1
#error "invald PRODUCT_BITBOXBASE_FACTORYSETUP value"
#endif

// Derive other useful definitions from the product.

#if PRODUCT_BITBOX_MULTI == 1
#define FACTORYSETUP 0
#endif

#if PRODUCT_BITBOX_BTCONLY == 1
#define FACTORYSETUP 0
#endif

#if PRODUCT_BITBOX_BASE == 1
#define FACTORYSETUP 0
#endif

#if PRODUCT_BITBOX02_FACTORYSETUP == 1
#define FACTORYSETUP 1
#endif

#if PRODUCT_BITBOXBASE_FACTORYSETUP == 1
#define FACTORYSETUP 1
#endif

#endif
