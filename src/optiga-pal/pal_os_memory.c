#include "optiga/pal/pal_os_memory.h"
#include "util.h"
#include <stdint.h>

void* pal_os_malloc(uint32_t block_size)
{
    void* res = malloc(block_size);
    traceln("Allocating %lu at %p", block_size, res);
    return res;
}

void* pal_os_calloc(uint32_t number_of_blocks, uint32_t block_size)
{
    return calloc(number_of_blocks, block_size);
}

void pal_os_free(void* block)
{
    traceln("Freeing %p", block);
    free(block);
}

void pal_os_memcpy(void* p_destination, const void* p_source, uint32_t size)
{
    memcpy(p_destination, p_source, size);
}

void pal_os_memset(void* p_buffer, uint32_t value, uint32_t size)
{
    memset(p_buffer, value, size);
}
