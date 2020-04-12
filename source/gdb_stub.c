
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <switch.h>

#include "gdb_stub.h"
#include "svc_dbg.h"
#include "error.h"

#define BUFFER_SIZE 512u
#define MAX_THREADS 20u
#define MAX_HW_BREAKPOINTS 4u

#define logf(fmt, ...) printf("gdb_stub: " fmt, ##__VA_ARGS__)

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

    gdb_stub_output_t output;
    void* arg;
    debug_event_t event;

    gdb_stub_thread_t thread[MAX_THREADS];
    u32 selected_thread;
    u64 code_addr;
    u32 exception_type;

    gdb_stub_breakpoint_t hw_breakpoints[MAX_HW_BREAKPOINTS];

    uint8_t mem[512];

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

typedef struct
{
    char type;
    bool (*func)(gdb_stub_t* stub, char* packet, size_t length);
} gdb_pkt_handler_t;

static bool gdb_stub_pkt_query(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_set(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_insert_breakpoint(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_remove_breakpoint(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_read_registers(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_write_registers(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_read_register(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_write_register(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_read_memory(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_write_memory(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_write_memory_bin(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_continue(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_step(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_get_halt_reason(gdb_stub_t* stub, char* packet, size_t length);

static const gdb_pkt_handler_t pkt_handler[] =
{
        { 'q', gdb_stub_pkt_query },
        { 'Q', gdb_stub_pkt_set },
        { 'Z', gdb_stub_pkt_insert_breakpoint },
        { 'z', gdb_stub_pkt_remove_breakpoint },
        { 'g', gdb_stub_pkt_read_registers },
        { 'G', gdb_stub_pkt_write_registers },
        { 'p', gdb_stub_pkt_read_register },
        { 'P', gdb_stub_pkt_write_register },
        { 'm', gdb_stub_pkt_read_memory },
        { 'M', gdb_stub_pkt_write_memory },
        { 'X', gdb_stub_pkt_write_memory_bin },
        { 'c', gdb_stub_pkt_continue },
        { 's', gdb_stub_pkt_step },
        { '?', gdb_stub_pkt_get_halt_reason },
};

typedef struct
{
    const char* query;
    bool (*func)(gdb_stub_t* stub, char* packet, size_t length);
} gdb_query_handler_t;

static bool gdb_stub_query_offsets(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_query_supported(gdb_stub_t* stub, char* packet, size_t length);

static const gdb_query_handler_t query_handler[] =
{
        { "Offsets", gdb_stub_query_offsets },
        { "Supported", gdb_stub_query_supported },
};

static const char hex_chars[] = "0123456789abcdef";

static const char* thread_list_header =
        "<?xml version=\"1.0\"?>\n"
        "<threads>\n";

static const char* thread_list_footer = "</threads>";
static const char* thread_list_fmt = "<thread id=\"%s\" name=\"%s\" />";

static void gdb_stub_send_packet(gdb_stub_t* stub, const char* packet);
static void gdb_stub_send_error(gdb_stub_t* stub, uint8_t err);
static void gdb_stub_send_signal(gdb_stub_t* stub, uint8_t signal);

static void list_processes(void)
{
    Result res;
    u64 our_pid;
    u64 pids[100];
    s32 num_pids = 0;

    // get our pid
    res = svcGetProcessId(&our_pid, CUR_PROCESS_HANDLE);
    if (R_FAILED(res))
    {
        return;
    }

    res = svcGetProcessList(&num_pids, pids, sizeof(pids));
    if (R_FAILED(res))
    {
        return;
    }

    printf("processes: \n");
    for(s32 i = 0; i < num_pids; ++i)
    {
        Handle proc;
        debug_event_t event;

        // don't try to debug our process
        if (pids[i] == our_pid)
        {
            continue;
        }

        res = svcDebugActiveProcess(&proc, pids[i]);
        if (R_FAILED(res))
        {
            continue;
        }

        while(R_SUCCEEDED(svcGetDebugEvent((u8*)&event, proc)))
        {
            if (event.type == DEBUG_EVENT_ATTACH_PROCESS)
            {
                printf("\t%s (0x%lX)\n", event.attach_process.process_name, event.attach_process.process_id);
                break;
            }
        }

        svcCloseHandle(proc);
    }

    printf("done\n");
}

static bool get_pid_by_name(const char* name, u64* pid)
{
    Result res;
    u64 our_pid;
    u64 pids[100];
    s32 num_pids = 0;

    // get our pid
    res = svcGetProcessId(&our_pid, CUR_PROCESS_HANDLE);
    if (R_FAILED(res))
    {
        return false;
    }

    res = svcGetProcessList(&num_pids, pids, sizeof(pids));
    if (R_FAILED(res))
    {
        return false;
    }

    for(s32 i = 0; i < num_pids; ++i)
    {
        Handle proc;
        debug_event_t event;
        bool found_pid = false;

        // don't try to debug our own process
        if (pids[i] == our_pid)
        {
            continue;
        }

        res = svcDebugActiveProcess(&proc, pids[i]);
        if (R_FAILED(res))
        {
            continue;
        }

        while(R_SUCCEEDED(svcGetDebugEvent((u8*)&event, proc)))
        {
            if (event.type == DEBUG_EVENT_ATTACH_PROCESS &&
                    strcmp(name, event.attach_process.process_name) == 0)
            {
                found_pid = true;
                break;
            }
        }

        svcCloseHandle(proc);

        if (found_pid)
        {
            *pid = pids[i];
            return true;
        }
    }

    return false;
}

gdb_stub_t* gdb_stub_create(gdb_stub_output_t output, void* arg)
{
    Result res;

    gdb_stub_t* stub = calloc(1u, sizeof(*stub));
    if(stub == NULL)
    {
        goto err;
    }

    stub->output = output;
    stub->arg = arg;
    stub->rx.state = CMD_STATE_START;

    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        stub->thread[i].tid = UINT64_MAX;
    }


    //list_processes();

#if 0
    Result res;
    res = svcDebugActiveProcess(&stub->session, 0x85);
    if(R_FAILED(res))
    {
        logf("svcDebugActiveProcess failed (%d-%d)\n", R_MODULE(res), R_DESCRIPTION(res));
        goto err_1;
    }
#else
    u64 pid;
    if(!get_pid_by_name("usb", &pid))
    {
        logf("get_pid_by_name failed\n");
        goto err_1;
    }
    else
    {
        logf("debugging 0x%lX\n", pid);
    }
    

    res = svcDebugActiveProcess(&stub->session, pid);
    if(R_FAILED(res))
    {
        logf("svcDebugActiveProcess failed (%d-%d)\n", R_MODULE(res), R_DESCRIPTION(res));
        goto err_1;
    }

    logf("svcDebugActiveProcess succeeded\n");
#endif

    return stub;
err_1:
    free(stub);
err:
    return NULL;
}

static uint8_t gdb_stub_decode_hex_char(char c)
{
    if ((c >= 'a') && (c <= 'f'))
        return (c - 'a' + 10);
    if ((c >= '0') && (c <= '9'))
        return (c - '0');
    if ((c >= 'A') && (c <= 'F'))
        return (c - 'A' + 10);

    return UINT8_MAX;
}

static int gdb_stub_decode_hex(const char* input, size_t input_len, void* output, size_t output_len)
{
    int dec_len = 0;

    if((input_len & 1) != 0u || output_len < input_len / 2u)
    {
        return -1;
    }

    for(size_t i = 0u; i < input_len / 2u; ++i)
    {
        uint8_t high = gdb_stub_decode_hex_char(input[i*2]);
        uint8_t low = gdb_stub_decode_hex_char(input[(i*2)+1]);
        if(high > 0xFu || low > 0xFu)
        {
            return -1;
        }

        ((uint8_t*)output)[i] = (high << 4u) | low;
        dec_len++;
    }

    return dec_len;
}

static void gdb_stub_putc(gdb_stub_t* stub, char c)
{
    stub->output(stub, &c, 1u, stub->arg);
}

static void gdb_stub_packet_begin(gdb_stub_t* stub)
{
    stub->tx.state = CMD_STATE_DATA;
    stub->tx.checksum = 0u;
    stub->tx.pos = 0u;

    stub->tx.cache[stub->tx.pos++] = '$';
}

static bool gdb_stub_packet_write(gdb_stub_t* stub, const char* data, size_t len)
{
    if(stub->tx.state != CMD_STATE_DATA)
    {
        return false;
    }

    while(len != 0u)
    {
        char c = *data;

        // flush the tx cache if it's full
        if(stub->tx.pos + 2u > sizeof(stub->tx.cache))
        {
            stub->output(stub, stub->tx.cache, stub->tx.pos, stub->arg);
            stub->tx.pos = 0u;
        }

        // escape reserved values
        if(c == '$' || c == '#' || c == '}')
        {
            stub->tx.cache[stub->tx.pos++] = '}';
            stub->tx.checksum += '}';
            c ^= 0x20;
        }

        stub->tx.cache[stub->tx.pos++] = c;
        stub->tx.checksum += c;
        data++;
        len--;
    }

    return true;
}

static bool gdb_stub_packet_write_hex_le(gdb_stub_t* stub, const void* data, size_t data_len)
{
    for(uint32_t i = 0u; i != data_len; ++i)
    {
        gdb_stub_packet_write(stub, &hex_chars[(((uint8_t*)data)[i] >> 4u) & 0xFu], 1u);
        gdb_stub_packet_write(stub, &hex_chars[((uint8_t*)data)[i] & 0xFu], 1u);
    }

    return true;
}

static bool gdb_stub_packet_write_hex_be(gdb_stub_t* stub, const void* data, size_t data_len)
{
    for(uint32_t i = data_len; i != 0u; --i)
    {
        gdb_stub_packet_write(stub, &hex_chars[(((uint8_t*)data)[i-1u] >> 4u) & 0xFu], 1u);
        gdb_stub_packet_write(stub, &hex_chars[((uint8_t*)data)[i-1u] & 0xFu], 1u);
    }

    return true;
}

static bool gdb_stub_packet_end(gdb_stub_t* stub)
{
    if(stub->tx.state != CMD_STATE_DATA)
    {
        return false;
    }

    // flush the tx cache if it's full
    if(stub->tx.pos + 3u > sizeof(stub->tx.cache))
    {
        stub->output(stub, stub->tx.cache, stub->tx.pos, stub->arg);
        stub->tx.pos = 0u;
    }

    stub->tx.cache[stub->tx.pos++] = '#';
    stub->tx.cache[stub->tx.pos++] = hex_chars[(stub->tx.checksum >> 4u) & 0xFu];
    stub->tx.cache[stub->tx.pos++] = hex_chars[stub->tx.checksum & 0xFu];

    // send the rest of the packet
    stub->output(stub, stub->tx.cache, stub->tx.pos, stub->arg);
    stub->tx.pos = 0u;
    stub->tx.state = CMD_STATE_START;

    return true;
}

static void gdb_stub_send_packet(gdb_stub_t* stub, const char* packet)
{
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, packet, strlen(packet));
    gdb_stub_packet_end(stub);
}

static void gdb_stub_send_error(gdb_stub_t* stub, uint8_t err)
{
    logf("<<<<<<<<<<<<<<<<<< gdb_stub_send_error (err=0x%X)\n", err);
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, "E", 1u);
    gdb_stub_packet_write_hex_le(stub, &err, sizeof(err));
    gdb_stub_packet_end(stub);
}

static void gdb_stub_send_signal(gdb_stub_t* stub, uint8_t sig)
{
    logf("<<<<<<<<<<<<<<<<<< gdb_stub_send_signal (signal=0x%X)\n", sig);
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, "S", 1u);
    gdb_stub_packet_write_hex_le(stub, &sig, sizeof(sig));
    gdb_stub_packet_end(stub);
}

static void gdb_stub_send_trap(gdb_stub_t* stub, const char* reason)
{
    u8 sig = 0x05u;
    logf("<<<<<<<<<<<<<<<<<< gdb_stub_send_trap (reason=%s)\n", reason);
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, "T", 1u);
    gdb_stub_packet_write_hex_le(stub, &sig, sizeof(sig));
    gdb_stub_packet_write(stub, reason, strlen(reason));
    gdb_stub_packet_end(stub);
}

static inline u32 gdb_stub_thread_id_to_index(gdb_stub_t* stub, u64 tid)
{
    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        if(stub->thread[i].tid == tid)
        {
            return i;
        }
    }

    return UINT32_MAX;
}

static void gdb_stub_pkt(gdb_stub_t* stub, char* packet, size_t length)
{
    bool handled = false;

    logf("got packet (%s)\n", packet);

    for(u32 i = 0u; i < sizeof(pkt_handler) / sizeof(pkt_handler[0]); ++i)
    {
        if(packet[0] == pkt_handler[i].type)
        {
            if(!pkt_handler[i].func(stub, packet, length))
            {
                gdb_stub_send_error(stub, 0u);
            }
            handled = true;
            break;
        }
    }

    if(!handled)
    {
        gdb_stub_send_packet(stub, "");
    }
}

static bool gdb_stub_pkt_query(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_query\n");

    for(u32 i = 0u; i < sizeof(query_handler) / sizeof(query_handler[0]); ++i)
    {
        if(memcmp(&packet[1], query_handler[i].query, strlen(query_handler[i].query)) == 0)
        {
            if(!query_handler[i].func(stub, packet, length))
            {
                return false;
            }
        }

    }

    gdb_stub_send_packet(stub, "");
    return true;
}

static bool gdb_stub_pkt_set(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_set\n");
    logf("%s not implemented\n", __FUNCTION__);
    gdb_stub_send_packet(stub, "");
    return true;
}

static bool gdb_stub_pkt_insert_breakpoint(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_insert_breakpoint\n");
    u64 addr;

    switch(packet[1])
    {
    case '1':
        if(sscanf(packet, "Z1,%lX", &addr) == 1)
        {
            bool bp_set = false;
            logf("setting hw breakpoint at address 0x%lX\n", addr);
            for(u32 i = 0u; i < MAX_HW_BREAKPOINTS; ++i)
            {
                if((stub->hw_breakpoints[i].flags & 1u) == 0u)
                {
                    stub->hw_breakpoints[i].flags = (0xFu << 5u) | 1u;
                    stub->hw_breakpoints[i].address = addr;

                    Result res = svcSetHardwareBreakPoint(i,
                            stub->hw_breakpoints[i].flags,
                            stub->hw_breakpoints[i].address);

                    if(R_SUCCEEDED(res))
                    {
                        bp_set = true;
                    }
                    else
                    {
                        stub->hw_breakpoints[i].flags = 0u;
                        stub->hw_breakpoints[i].address = 0u;

                        logf("svcSetHardwareBreakPoint failed (err=%d-%d, id=%u, flags=0x%lX, addr=0x%lX)\n",
                                R_MODULE(res), R_DESCRIPTION(res),
                                i,
                                stub->hw_breakpoints[i].flags,
                                stub->hw_breakpoints[i].address);
                    }
                    break;
                }
            }

            if(bp_set)
            {
                gdb_stub_send_packet(stub, "OK");
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
        break;
    default:
        gdb_stub_send_packet(stub, "");
        return true;
    }

    return true;
}

static bool gdb_stub_pkt_remove_breakpoint(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_remove_breakpoint\n");
    u64 addr;

    switch(packet[1])
    {
    case '1':
        if(sscanf(packet, "z1,%lX", &addr) == 1)
        {
            for(u32 i = 0u; i < MAX_HW_BREAKPOINTS; ++i)
            {
                if(stub->hw_breakpoints[i].address == addr)
                {
                    stub->hw_breakpoints[i].flags = 0u;
                    stub->hw_breakpoints[i].address = 0u;

                    Result res = svcSetHardwareBreakPoint(i,
                            stub->hw_breakpoints[i].flags,
                            stub->hw_breakpoints[i].address);

                    if(R_FAILED(res))
                    {
                        logf("svcSetHardwareBreakPoint failed (err=%d-%d, id=%u, flags=0x%lX, addr=0x%lX)\n",
                                R_MODULE(res), R_DESCRIPTION(res),
                                i,
                                stub->hw_breakpoints[i].flags,
                                stub->hw_breakpoints[i].address);
                    }
                    break;
                }
            }

            gdb_stub_send_packet(stub, "OK");
        }
        else
        {
            return false;
        }
        break;
    default:
        gdb_stub_send_packet(stub, "");
        return true;
    }

    return true;
}

static bool gdb_stub_pkt_read_registers(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_read_registers\n");

    u32 idx = stub->selected_thread;

    if(idx >= MAX_THREADS ||
            stub->thread[idx].tid == UINT64_MAX)
    {
        logf("selected thread is invalid\n");
        return false;
    }

    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write_hex_le(stub, &stub->thread[idx].ctx, 788u);
    gdb_stub_packet_end(stub);

    return true;
}

static bool gdb_stub_pkt_write_registers(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_write_registers\n");
    logf("%s not implemented\n", __FUNCTION__);
    return false;
}

static bool gdb_stub_pkt_read_register(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_read_register\n");
    logf("%s not implemented\n", __FUNCTION__);
    return false;
}

static bool gdb_stub_pkt_write_register(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_write_register\n");
    logf("%s not implemented\n", __FUNCTION__);
    return false;
}

static bool gdb_stub_pkt_read_memory(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_read_memory\n");

    Result res;
    u64 addr, size;

    if(sscanf(packet, "m%lx,%lx", &addr, &size) != 2)
    {
        logf("error parsing read memory packet\n");
        return false;
    }

    gdb_stub_packet_begin(stub);

    while(size != 0u)
    {
        size_t chunk = size;
        if(chunk > sizeof(stub->mem))
        {
            chunk = sizeof(stub->mem);
        }

        res = svcReadDebugProcessMemory(stub->mem, stub->session, addr, chunk);
        if(R_SUCCEEDED(res))
        {
            gdb_stub_packet_write_hex_le(stub, stub->mem, chunk);
        }
        else
        {
            logf("svcReadDebugProcessMemory failed (err=0x%X, addr=0x%lX, size=0x%lX)\n", res, addr, size);
            break;
        }

        size -= chunk;
        addr += chunk;
    }

    gdb_stub_packet_end(stub);

    return true;
}

static bool gdb_stub_pkt_write_memory(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_write_memory\n");
    logf("%s not implemented\n", __FUNCTION__);
    return false;
}

static bool gdb_stub_pkt_write_memory_bin(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_write_memory_bin\n");
    u64 addr, write_len;
    size_t pos = 0u;

    while(pos < length && packet[pos] != ':')
    {
        pos++;
    }

    if(pos == length)
    {
        return false;
    }

    packet[pos] = '\0';

    if(sscanf(packet, "X%lX,%lX", &addr, &write_len) != 2)
    {
        return false;
    }

    if(write_len != length - pos - 1u)
    {
        logf("length doesn't match packet\n");
        return false;
    }

    if(write_len != 0u &&
            R_FAILED(svcWriteDebugProcessMemory(stub->session, &packet[pos+1u], addr, write_len)))
    {
        logf("svcWriteDebugProcessMemory failed (addr=0x%lX, len=0x%lX)\n", addr, write_len);
        return false;
    }

    gdb_stub_send_packet(stub, "OK");
    return true;
}

static bool gdb_stub_pkt_continue(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_continue\n");

    Result res = svcContinueDebugEvent(stub->session, 0x4u, NULL, 0u);
    if(R_FAILED(res))
    {
        return false;
    }

    return true;
}

static bool gdb_stub_pkt_step(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_step\n");

    Result res = svcContinueDebugEvent(stub->session, 0x4u, NULL, 0u);
    if(R_FAILED(res))
    {
        return false;
    }

    return true;
}

static void gdb_stub_send_stop_reply(gdb_stub_t* stub)
{
    const char* reason = "";

    switch(stub->exception_type)
    {
    case DEBUG_EXCEPTION_TRAP:
        reason = "swbreak";
        break;
    case DEBUG_EXCEPTION_INSTRUCTION_ABORT:
        break;
    case DEBUG_EXCEPTION_DATA_ABORT_MISC:
        break;
    case DEBUG_EXCEPTION_PC_SP_ALIGNMENT_FAULT:
        break;
    case DEBUG_EXCEPTION_DEBUGGER_ATTACHED:
        break;
    case DEBUG_EXCEPTION_BREAKPOINT:
        reason = "hwbreak";
        break;
    case DEBUG_EXCEPTION_USER_BREAK:
        break;
    case DEBUG_EXCEPTION_DEBUGGER_BREAK:
        break;
    case DEBUG_EXCEPTION_BAD_SVC_ID:
        break;
    case DEBUG_EXCEPTION_SERROR:
        break;
    }

    if(*reason == '\0')
    {
        gdb_stub_send_signal(stub, 0u);
    }
    else
    {
        gdb_stub_send_trap(stub, reason);
    }
}

static bool gdb_stub_pkt_get_halt_reason(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_get_halt_reason\n");
    gdb_stub_send_stop_reply(stub);
    return true;
}

static bool gdb_stub_query_offsets(gdb_stub_t* stub, char* packet, size_t length)
{
    const char* text_str = "TextSeg=";
    u64 addr = stub->code_addr;

    logf("gdb_stub_query_offsets (TextSeg=0x%lX)\n", addr);

    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, text_str, strlen(text_str));
    gdb_stub_packet_write_hex_be(stub, &addr, sizeof(addr));
    gdb_stub_packet_end(stub);

    return true;
}

static bool gdb_stub_query_supported(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_query_supported\n");
    gdb_stub_send_packet(stub, "hwbreak+");
    return true;
}

static inline void gdb_stub_insert_char(gdb_stub_t* stub, char c)
{
    switch(stub->rx.state)
    {
    case CMD_STATE_START:
        if(c == '$')
        {
            stub->rx.state = CMD_STATE_DATA;
            stub->rx.pos = 0u;
            stub->rx.checksum = 0u;
        }
        else if(c == 0x03u)
        {
            logf("got break request\n");
            svcBreakDebugProcess(stub->session);
            gdb_stub_send_packet(stub, "OK");
        }
        break;
    case CMD_STATE_DATA:
        if(c == '$')
        {
            stub->rx.state = CMD_STATE_START;
        }
        else if(c == '#')
        {
            stub->rx.state = CMD_STATE_CHECKSUM;
            stub->rx.checksum_pos = 0u;
        }
        else if(c == '}')
        {
            stub->rx.state = CMD_STATE_ESC;
            stub->rx.checksum += (uint8_t)c;
        }
        else if(stub->rx.pos < BUFFER_SIZE-1)
        {
            stub->rx.packet[stub->rx.pos++] = c;
            stub->rx.checksum += (uint8_t)c;
        }
        else
        {
            // buffer too small
            stub->rx.state = CMD_STATE_START;
            gdb_stub_send_error(stub, 0);
        }
        break;
    case CMD_STATE_ESC:
        if(stub->rx.pos < BUFFER_SIZE-1)
        {
            stub->rx.checksum += (uint8_t)c;
            stub->rx.packet[stub->rx.pos++] = c ^ 0x20;
            stub->rx.state = CMD_STATE_DATA;
        }
        else
        {
            // buffer too small
            stub->rx.state = CMD_STATE_START;
            gdb_stub_send_error(stub, 0);
        }
        break;
    case CMD_STATE_CHECKSUM:
        stub->rx.checksum_buf[stub->rx.checksum_pos++] = c;

        if(stub->rx.checksum_pos == 2u)
        {
            uint8_t checksum;
            if(gdb_stub_decode_hex(stub->rx.checksum_buf, 2u, &checksum, sizeof(checksum)) == 1
                    && checksum == stub->rx.checksum)
            {
                // null terminate the packet
                stub->rx.packet[stub->rx.pos] = '\0';

                gdb_stub_putc(stub, '+');
                gdb_stub_pkt(stub, stub->rx.packet, stub->rx.pos);
            }
            else
            {
                logf("bad checksum\n");
                gdb_stub_putc(stub, '-');
            }

            stub->rx.state = CMD_STATE_START;
        }
        break;
    }
}

void gdb_stub_input(gdb_stub_t* stub, const char* buffer, size_t length)
{
    while(length != 0u)
    {
        gdb_stub_insert_char(stub, *buffer);
        buffer++;
        length--;
    }
}

void gdb_stub_destroy(gdb_stub_t* stub)
{
    memset(stub, 0, sizeof(*stub));
    free(stub);
}

Result gdb_stub_get_waiter(gdb_stub_t* stub, Waiter* waiter)
{
    if(stub->session != INVALID_HANDLE)
    {
        *waiter = waiterForHandle(stub->session);
        return 0;
    }

    return MAKERESULT(Module_SysGdbStub, SysGdbStubError_NoActiveSession);
}

static void print_debug_event(debug_event_t* event)
{
    static const char* debug_event_str[] =
    {
            "DebugEvent_AttachProcess",
            "DebugEvent_AttachThread",
            "DebugEvent_ExitProcess",
            "DebugEvent_ExitThread",
            "DebugEvent_Exception",
    };

    static const char* exit_type_str[] =
    {
            "ExitType_PausedThread",
            "ExitType_RunningThread",
            "ExitType_ExitedProcess",
            "ExitType_TerminatedProcess",
    };

    static const char* exception_type_str[] =
    {
            "ExceptionType_Trap",
            "ExceptionType_InstructionAbort",
            "ExceptionType_DataAbortMisc",
            "ExceptionType_PcSpAlignmentFault",
            "ExceptionType_DebuggerAttached",
            "ExceptionType_BreakPoint",
            "ExceptionType_UserBreak",
            "ExceptionType_DebuggerBreak",
            "ExceptionType_BadSvcId",
            "ExceptionType_SError",
    };

    logf("%s\n", debug_event_str[event->type]);
    switch(event->type)
    {
    case DEBUG_EVENT_ATTACH_PROCESS:
        logf("\tTitleId: 0x%lX\n", event->attach_process.title_id);
        logf("\tProcessId: 0x%lX\n", event->attach_process.process_id);
        logf("\tProcessName: %s\n", event->attach_process.process_name);
        logf("\tMmuFlags: 0x%X\n", event->attach_process.mmu_flags);
        logf("\tUserExceptionContextAddr: 0x%lX\n", event->attach_process.user_exception_context_addr);
        break;
    case DEBUG_EVENT_ATTACH_THREAD:
        logf("\tThreadId: 0x%lX\n", event->attach_thread.thread_id);
        logf("\tTlsPtr: 0x%lX\n", event->attach_thread.tls_ptr);
        logf("\tEntrypoint: 0x%lX\n", event->attach_thread.entry_point);
        break;
    case DEBUG_EVENT_EXIT_PROCESS:
    case DEBUG_EVENT_EXIT_THREAD:
        logf("\t%s\n", exit_type_str[event->exit.type]);
        break;
    case DEBUG_EVENT_EXCEPTION:
        logf("\t%s\n", exception_type_str[event->exception.type]);
        switch(event->exception.type)
        {
        case DEBUG_EXCEPTION_TRAP:
            logf("\t\tOpcode: %u\n", event->exception.trap.opcode);
            break;
        case DEBUG_EXCEPTION_BREAKPOINT:
            logf("\t\tIsWatchpoint: %u\n", event->exception.breakpoint.is_watchpoint);
            break;
        case DEBUG_EXCEPTION_USER_BREAK:
            logf("\t\tInfo0: %u\n", event->exception.user_break.info0);
            logf("\t\tInfo1: %lu\n", event->exception.user_break.info1);
            logf("\t\tInfo2: %lu\n", event->exception.user_break.info2);
            break;
        case DEBUG_EXCEPTION_BAD_SVC_ID:
            logf("\t\tSvcId: %u\n", event->exception.bad_svc_id.svc_id);
            break;
        }
    }
}

static void gdb_stub_exception(gdb_stub_t* stub, const debug_exception_t* exception)
{
    stub->exception_type = exception->type;
    
    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        if(stub->thread[i].tid != UINT64_MAX)
        {
            svcGetDebugThreadContext(&stub->thread[i].ctx, stub->session, stub->thread[i].tid, 0xFu);
        }
    }

    gdb_stub_send_stop_reply(stub);
}

static void gdb_stub_attach_thread(gdb_stub_t* stub, u64 thread_id)
{
    u32 thread_idx = gdb_stub_thread_id_to_index(stub, thread_id);

    // find a free slot for the new thread
    if(thread_idx == UINT32_MAX)
    {
        for(u32 i = 0u; i < MAX_THREADS; ++i)
        {
            if(stub->thread[i].tid == UINT64_MAX)
            {
                thread_idx = i;
                break;
            }
        }
    }

    // check if we've exceeded max threads
    if(thread_idx == UINT32_MAX)
    {
        logf("exceeded max threads\n");
        return;
    }

    // store the thread and read the context
    stub->thread[thread_idx].tid = thread_id;
    svcGetDebugThreadContext(&stub->thread[thread_idx].ctx, stub->session, thread_id, 0xFu);
    logf("thread %lu attached\n", thread_id);
}

static void gdb_stub_exit_thread(gdb_stub_t* stub, u64 thread_id)
{
    u32 idx = gdb_stub_thread_id_to_index(stub, thread_id);
    if(idx < MAX_THREADS)
    {
        logf("thread %lu detached\n", thread_id);
        memset(&stub->thread[idx], 0, sizeof(stub->thread[idx]));
        stub->thread[idx].tid = UINT64_MAX;
    }
}

static void gdb_stub_event(gdb_stub_t* stub, const debug_event_t* event)
{
    print_debug_event(&stub->event);

    switch(event->type)
        {
        case DEBUG_EVENT_ATTACH_PROCESS:
            break;
        case DEBUG_EVENT_ATTACH_THREAD:
            if(stub->code_addr == 0u)
            {
                stub->code_addr = event->attach_thread.entry_point;
            }
            gdb_stub_attach_thread(stub, event->thread_id);
            break;
        case DEBUG_EVENT_EXIT_PROCESS:
            break;
        case DEBUG_EVENT_EXIT_THREAD:
            gdb_stub_exit_thread(stub, event->thread_id);
            break;
        case DEBUG_EVENT_EXCEPTION:
            gdb_stub_exception(stub, &event->exception);
            break;
        }
}

void gdb_stub_handle_events(gdb_stub_t* stub)
{
    if(stub->session == INVALID_HANDLE)
    {
        return;
    }

    waitSingleHandle(stub->session, 0u);

    while(R_SUCCEEDED(svcGetDebugEvent((u8*)&stub->event, stub->session)))
    {
        gdb_stub_event(stub, &stub->event);
    }
}
