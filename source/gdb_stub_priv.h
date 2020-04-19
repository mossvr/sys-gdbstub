
#ifndef GDB_STUB_PRIV_H_
#define GDB_STUB_PRIV_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <switch.h>

#include "gdb_stub.h"
#include "svc_dbg.h"

#define BUFFER_SIZE 512u
#define MAX_THREADS 20u
#define MAX_HW_BREAKPOINTS 4u

#if 1
#define logf(fmt, ...) printf("gdb_stub: " fmt, ##__VA_ARGS__)
#else
#define logf(fmt, ...)
#endif

typedef enum
{
    CMD_STATE_START,
    CMD_STATE_DATA,
    CMD_STATE_ESC,
    CMD_STATE_CHECKSUM,
} cmd_state_t;

typedef struct
{
    u64 tid;
    ThreadContext ctx;
} gdb_stub_thread_t;

typedef struct
{
    u64 address;
    u64 flags;
} gdb_stub_breakpoint_t;

struct gdb_stub
{
    Handle session;
    u64 pid;

    gdb_stub_output_t output;
    void* arg;
    debug_event_t event;

    gdb_stub_thread_t thread[MAX_THREADS];
    u32 selected_thread;
    u64 base_addr;
    u32 exception_type;

    gdb_stub_breakpoint_t hw_breakpoints[MAX_HW_BREAKPOINTS];

    uint8_t mem[512];
    char xfer[8192];
    size_t xfer_len;

    struct
    {
        char packet[BUFFER_SIZE];
        cmd_state_t state;
        size_t pos;
        char checksum_buf[2];
        size_t checksum_pos;
        uint8_t checksum;
    } rx;

    struct
    {
        cmd_state_t state;
        uint8_t checksum;
        char cache[BUFFER_SIZE];
        size_t pos;
    } tx;
};

int gdb_stub_decode_hex(const char* input, size_t input_len, void* output, size_t output_len);
bool gdb_stub_parse_thread_id(const char* input, s64* o_pid, s64* o_tid);
u32 gdb_stub_thread_id_to_index(gdb_stub_t* stub, u64 tid);

void gdb_stub_putc(gdb_stub_t* stub, char c);
void gdb_stub_send_packet(gdb_stub_t* stub, const char* packet);
void gdb_stub_send_error(gdb_stub_t* stub, uint8_t err);
void gdb_stub_send_stop_reply(gdb_stub_t* stub);

void gdb_stub_packet_begin(gdb_stub_t* stub);
bool gdb_stub_packet_write(gdb_stub_t* stub, const char* data, size_t len);
bool gdb_stub_packet_write_hex_le(gdb_stub_t* stub, const void* data, size_t data_len);
bool gdb_stub_packet_write_hex_be(gdb_stub_t* stub, const void* data, size_t data_len);
bool gdb_stub_packet_write_str(gdb_stub_t* stub, const void* str);
bool gdb_stub_packet_end(gdb_stub_t* stub);

void gdb_stub_pkt(gdb_stub_t* stub, char* packet, size_t length);
bool gdb_stub_pkt_query(gdb_stub_t* stub, char* packet, size_t length);
bool gdb_stub_query_xfer(gdb_stub_t* stub, char* packet, size_t length);

bool gdb_stub_attach(gdb_stub_t* stub, u64 pid);
bool gdb_stub_detach(gdb_stub_t* stub, u64 pid);

#endif /* GDB_STUB_PRIV_H_ */
