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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define UTIL_BUFFER_LEN 0x1000
#define MIN(a, b)                                       \
    __extension__({                                     \
        _Pragma("GCC diagnostic push");                 \
        _Pragma("GCC diagnostic ignored \"-Wshadow\""); \
        __typeof__(a) _a = (a);                         \
        __typeof__(b) _b = (b);                         \
        _Pragma("GCC diagnostic pop");                  \
        _a > _b ? _b : _a;                              \
    })
#define MAX(a, b)                                       \
    __extension__({                                     \
        _Pragma("GCC diagnostic push");                 \
        _Pragma("GCC diagnostic ignored \"-Wshadow\""); \
        __typeof__(a) _a = (a);                         \
        __typeof__(b) _b = (b);                         \
        _Pragma("GCC diagnostic pop");                  \
        _a > _b ? _a : _b;                              \
    })
#define strlens(s) ((s) == NULL ? 0 : strlen(s))
#define STREQ(a, b) (strcmp((a), (b)) == 0)
#define MEMEQ(a, b, c) (memcmp((a), (b), (c)) == 0)
#define SIGMOID(a) (0.0018F * (a)*abs(a) / (1 + 0.002F * (a) * (a)));

// We define our own true false which are more secure than stdbool true/false becuase it requires
// flipping many more bits.
// It is recommended to always compare against sectrue, even in the false case.
typedef uint32_t secbool_u32;
#define sectrue_u32 0x55555555u
#define secfalse_u32 0x00000000u

typedef uint8_t secbool_u8;
#define sectrue_u8 0x55u
#define secfalse_u8 0x00u

void util_zero(volatile void* dst, size_t len);
void util_clear_buffers(void);

// `out` must be of size in_len*2+1. Use BB_HEX_SIZE() to compute the size.
void util_uint8_to_hex(const uint8_t* in_bin, size_t in_len, char* out);

#define BB_HEX_SIZE(in_bin) (sizeof((in_bin)) * 2 + 1)

void util_reverse_bin(uint8_t* b, int len);

void util_cleanup_str(char** str);
#define UTIL_CLEANUP_STR(var) \
    char* __attribute__((__cleanup__(util_cleanup_str))) var##_clean __attribute__((unused)) = var;

void util_cleanup_20(uint8_t** buf);
void util_cleanup_32(uint8_t** buf);
void util_cleanup_64(uint8_t** buf);

/**
 * Creates a duplicate of a string.
 * Guaranteed to return non-NULL (aborts if allocation fails).
 */
char* util_strdup(const char* str);

/**
 * Like sprintf, but creates the result buffer with the appropriate size.
 * Guaranteed to return non-NULL (aborts if allocation fails).
 *
 * @param fmt Printf-like format string. 
 */
__attribute__ ((format (printf, 1, 2)))
char* util_asprintf(const char* fmt, ...);

#define UTIL_CLEANUP_20(var)                                                                     \
    uint8_t* __attribute__((__cleanup__(util_cleanup_20))) var##_clean __attribute__((unused)) = \
        var;
#define UTIL_CLEANUP_32(var)                                                                     \
    uint8_t* __attribute__((__cleanup__(util_cleanup_32))) var##_clean __attribute__((unused)) = \
        var;
#define UTIL_CLEANUP_64(var)                                                                     \
    uint8_t* __attribute__((__cleanup__(util_cleanup_64))) var##_clean __attribute__((unused)) = \
        var;

/**
 * adds b to a safely.
 * @return Returns false if the operation would overflow.
 */
bool safe_uint64_add(uint64_t* a, uint64_t b);

#if defined(__GNUC__)
#define UTIL_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define UTIL_WARN_UNUSED_RESULT
#endif

/**
 * Tracing tools. Only enabled in semihosting builds
 *
 * Since we are using C99 it is necessary to provide at least 1 argument to "...". To print a
 * string, provide the format string "%s" and your string as the second argument.
 *
 * "do {} while" is a hack to make a macro work like a function in some cases.
 *
 * stderr is not buffered and takes forever to print stdout is used instead.
 *
 * SOURCE_PATH_SIZE is a definition provided from the command line which is the length of the path
 * to the project directory.
 */

#if defined(SEMIHOSTING)
#define LOG_LEVEL 1
#else
#define LOG_LEVEL 0
#endif
#define FILENAME (&__FILE__[SOURCE_PATH_SIZE])

#define trace(format, ...)                                                                     \
    do {                                                                                       \
        if (LOG_LEVEL > 0) fprintf(stdout, "%s:%d: " format, FILENAME, __LINE__, __VA_ARGS__); \
    } while (0)

#define traceln(format, ...)                                                         \
    do {                                                                             \
        if (LOG_LEVEL > 0)                                                           \
            fprintf(stdout, "%s:%d: " format "\n", FILENAME, __LINE__, __VA_ARGS__); \
    } while (0)

/**
 * Struct definining a rw buffer (buffer + length).
 */
typedef struct {
    /** Data buffer. */
    uint8_t* data;
    /** Actual length of the data. */
    size_t len;
    /** Maximum buffer capacity. */
    const size_t max_len;
} buffer_t;

/**
 * Struct definining a read-only buffer (buffer + length).
 */
typedef struct {
    /** Data buffer. */
    const uint8_t* data;
    /** Length of data contained in data. */
    const size_t len;
} in_buffer_t;

/**
 * Enum used to represent the result of an operation
 * which might return true, false, or "not finished yet".
 */
typedef enum { ASYNC_OP_TRUE, ASYNC_OP_FALSE, ASYNC_OP_NOT_READY } async_op_result_t;

/**
 * Allocate memory. Abort
 * if malloc fails.
 *
 * @param[in] size Number of bytes to allocate. Gets passed to malloc(2).
 * @return Allocated pointer. Guaranteed to be non-NULL.
 */
__attribute__((malloc))
void* util_malloc(size_t size);

#endif
