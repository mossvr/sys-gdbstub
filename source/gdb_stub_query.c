
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "gdb_stub_priv.h"

typedef struct
{
    const char* query;
    bool (*func)(gdb_stub_t* stub, char* packet, size_t length);
} gdb_query_handler_t;

static bool gdb_stub_query_thread_id(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_query_offsets(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_query_supported(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_query_attached(gdb_stub_t* stub, char* packet, size_t length);

static const gdb_query_handler_t query_handler[] =
{
        { "C", gdb_stub_query_thread_id },
        { "Offsets", gdb_stub_query_offsets },
        { "Supported", gdb_stub_query_supported },
        { "Attached", gdb_stub_query_attached },
        { "Xfer", gdb_stub_query_xfer },
};


bool gdb_stub_pkt_query(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);

    for (size_t i = 0u; i < sizeof(query_handler) / sizeof(query_handler[0]); ++i)
    {
        if (strncmp(&packet[1], query_handler[i].query, strlen(query_handler[i].query)) == 0)
        {
            return query_handler[i].func(stub, packet, length);
        }
    }

    return false;
}

static bool gdb_stub_query_thread_id(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    int tid = 0;
    int idx = stub->selected_thread;
    if (idx < MAX_THREADS)
    {
        tid = stub->thread[idx].tid;
    }

    logf("pid=%d, tid=%d\n", stub->pid, tid);

    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write_str(stub, "QC");
    gdb_stub_packet_write_thread_id(stub, stub->pid, tid);
    gdb_stub_packet_end(stub);
    
    return true;
}

static bool gdb_stub_query_offsets(gdb_stub_t* stub, char* packet, size_t length)
{
    const char* text_str = "TextSeg=";
    u64 addr = stub->base_addr;

    logf("gdb_stub_query_offsets (TextSeg=0x%lX)\n", addr);

    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, text_str, strlen(text_str));
    gdb_stub_packet_write_hex_be(stub, &addr, sizeof(addr));
    gdb_stub_packet_end(stub);

    return true;
}

static bool gdb_stub_query_supported(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);

    char* buf = (char*)stub->mem;
    size_t buf_len = sizeof(stub->mem);

    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write_str(stub, "multiprocess+;hwbreak+;qXfer:osdata:read+;qXfer:threads:read+");

    snprintf(buf, buf_len, ";PacketSize=%x", BUFFER_SIZE - 1u);
    gdb_stub_packet_write_str(stub, buf);

    gdb_stub_packet_end(stub);
    return true;
}

static bool gdb_stub_query_attached(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    gdb_stub_send_packet(stub, "1");
    return true;
}
