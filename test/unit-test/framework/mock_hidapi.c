#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <util.h>

// POSIX
#include <pthread.h>

#include <hidapi/hidapi.h>
#include <mock_workflow.h>

#include "queue.h"
#include "u2f.h"
#include "u2f/u2f_packet.h"
#include "usb/usb_processing.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define BUFSIZE 0x40LU

static uint8_t _buf[BUFSIZE];
static size_t _buf_len;
static bool _expect_more;

static bool _have_data;
static pthread_t thread;
static bool timer_thread_stop;
static pthread_mutex_t mutex;

static void _delay(uint32_t msec)
{
    struct timespec rem;
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = msec * 1000000,
    };
    nanosleep(&ts, &rem);
}

// function for sending packets?
static void _send_packet_cb(void)
{
    // printf("send\n");
}

void* timer_task(void* args)
{
    (void)args;
    for (;;) {
        // printf("tick\n");
        u2f_packet_timeout_tick();
        _delay(40);
        pthread_mutex_lock(&mutex);
        if (timer_thread_stop) {
            pthread_mutex_unlock(&mutex);
            return 0;
        }
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}

int hid_exit(void)
{
    return 0;
}

int hid_init(void)
{
    return 0;
}

void hid_close(hid_device* dev)
{
    pthread_mutex_lock(&mutex);
    timer_thread_stop = true;
    pthread_mutex_unlock(&mutex);
    void* retval;
    int res = pthread_join(thread, &retval);
    if (res != 0) {
        printf("Failed to join thread\n");
    }
}

hid_device* hid_open_path(const char* path)
{
    static char sham[] = "sham";
    usb_processing_init();
    u2f_device_setup();
    usb_processing_set_send(usb_processing_u2f(), _send_packet_cb);
    timer_thread_stop = false;
    int res = pthread_create(&thread, NULL, &timer_task, NULL);
    if (res != 0) {
        printf("failed to create thread\n");
    }
    pthread_mutex_init(&mutex, NULL);
    return (hid_device*)&sham;
}

int hid_write(hid_device* dev, const unsigned char* data, size_t length)
{
    if (length > BUFSIZE + 1) {
        printf("Internal test error: %lu > %lu\n", length - 1, BUFSIZE);
        return 0;
    }
    memcpy(_buf, data + 1, length - 1);
    _buf_len = length - 1;
    _expect_more = u2f_packet_process((const USB_FRAME*)_buf);
    if (!_expect_more) {
        // printf("Got complete packet\n");
        _have_data = true;
    }
    _delay(2);
    return length;
}

int hid_read_timeout(hid_device* dev, unsigned char* data, size_t length, int milliseconds)
{
    if (_expect_more || !_have_data) {
        if (_expect_more) {
            // printf("Internal error: expected more before read\n");
        }
        if (!_have_data) {
            // printf("No data yet\n");
        }
        _delay(600);
        usb_processing_process(usb_processing_u2f());
    }
    usb_processing_process(usb_processing_u2f());
    uint8_t* p = queue_pull(queue_u2f_queue());
    // printf("Queue: %p\n", p);
    if (p != NULL) {
        memcpy(data, p, MIN(length, BUFSIZE));
    } else {
        // printf("No data in queue\n");
        _delay(600);
        return -127;
    }
    if (queue_peek(queue_u2f_queue()) == NULL) {
        _have_data = false;
    }
    _expect_more = false;
    _delay(2);
    return length;
}

struct hid_device_info* hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
    static struct hid_device_info dev = {
        .path = "sham",
        .vendor_id = 0x03eb,
        .product_id = 0x2403,
        .manufacturer_string = L"mock",
        .product_string = L"mock",
        .next = NULL,
    };
    return &dev;
}

void hid_free_enumeration(struct hid_device_info* devs) {}

#pragma GCC diagnostic pop

void __wrap_workflow_status_blocking(const char* msg, bool status_success) {}

workflow_t* __wrap_workflow_unlock(void(cb)(bool, void*), void* cb_param)
{
    return mock_workflow_unlock(5, true, cb, cb_param);
}
