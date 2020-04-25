
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "gdb_stub_priv.h"

#define ARMV8_BRK(imm) (0xD4200000 | (((imm) & 0xFFFF) << 5))

typedef struct
{
    const char* type;
    bool (*func)(gdb_stub_t* stub, char* packet, size_t length);
} gdb_pkt_handler_t;

static bool gdb_stub_pkt_set(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_set_thread(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_thread_alive(gdb_stub_t* stub, char* packet, size_t length);
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
static bool gdb_stub_pkt_detach(gdb_stub_t* stub, char* packet, size_t length);
static bool gdb_stub_pkt_attach(gdb_stub_t* stub, char* packet, size_t length);

static const gdb_pkt_handler_t pkt_handler[] =
{
        { "q", gdb_stub_pkt_query },
        { "Q", gdb_stub_pkt_set },
        { "H", gdb_stub_pkt_set_thread },
        { "T", gdb_stub_pkt_thread_alive },
        { "Z", gdb_stub_pkt_insert_breakpoint },
        { "z", gdb_stub_pkt_remove_breakpoint },
        { "g", gdb_stub_pkt_read_registers },
        { "G", gdb_stub_pkt_write_registers },
        { "p", gdb_stub_pkt_read_register },
        { "P", gdb_stub_pkt_write_register },
        { "m", gdb_stub_pkt_read_memory },
        { "M", gdb_stub_pkt_write_memory },
        { "X", gdb_stub_pkt_write_memory_bin },
        { "c", gdb_stub_pkt_continue },
        { "s", gdb_stub_pkt_step },
        { "?", gdb_stub_pkt_get_halt_reason },
        { "D", gdb_stub_pkt_detach },
        { "vAttach", gdb_stub_pkt_attach },
};

void gdb_stub_pkt(gdb_stub_t* stub, char* packet, size_t length)
{
    bool handled = false;

    logf("got packet (%s)\n", packet);

    for(u32 i = 0u; i < sizeof(pkt_handler) / sizeof(pkt_handler[0]); ++i)
    {
        if (strncmp(packet, pkt_handler[i].type, strlen(pkt_handler[i].type)) == 0)
        {
            handled = pkt_handler[i].func(stub, packet, length);
            break;
        }
    }

    if(!handled)
    {
        gdb_stub_send_packet(stub, "");
    }
}

static bool gdb_stub_pkt_set(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    logf("%s not implemented\n", __FUNCTION__);
    return false;
}

static bool gdb_stub_pkt_set_thread(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    int pid, tid;
    char* op = &packet[1];

    if (*op != 'g')
    {
        goto err;
    }

    if (!gdb_stub_parse_thread_id(packet+2, &pid, &tid))
    {
        goto err;
    }

    if (pid > 0 && pid != stub->pid)
    {
        goto err;
    }

    if (tid <= 0)
    {
        stub->selected_thread = -1;
        gdb_stub_send_packet(stub, "OK");
        return true;
    }
    else
    {
        for (int i = 0; i < MAX_THREADS; ++i)
        {
            if (stub->thread[i].tid == tid)
            {
                stub->selected_thread = i;
                logf("selected thread (tid=%d, idx=%u)\n", tid, i);
                gdb_stub_send_packet(stub, "OK");
                return true;
            }
        }
    }

err:
    gdb_stub_send_error(stub, 0u);
    return true;
}

static bool gdb_stub_pkt_thread_alive(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    int pid, tid;

    if (!gdb_stub_parse_thread_id(packet+1, &pid, &tid))
    {
        goto err;
    }

    if ((pid > 0 && pid != stub->pid) || tid <= 0)
    {
        goto err;
    }

    int idx = gdb_stub_thread_id_to_index(stub, tid);
    if (idx < MAX_THREADS)
    {
        gdb_stub_send_packet(stub, "OK");
        return true;
    }

err:
    gdb_stub_send_error(stub, 0u);
    return true;
}

static bool gdb_stub_pkt_insert_breakpoint(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_insert_breakpoint\n");

    if (length < 4)
    {
        gdb_stub_send_error(stub, 0u);
        return true;
    }

    Result res;
    bool bp_set = false;
    char type = packet[1];
    u64 addr = strtoul(&packet[3], NULL, 16);

    if (type == '0')
    {
        for (int i = 0; i < MAX_SW_BREAKPOINTS; ++i)
        {
            sw_breakpoint_t* bp = &stub->sw_breakpoints[i];
            if (bp->address == UINT64_MAX)
            {
                bp->address = addr;

                res = svcReadDebugProcessMemory(&bp->value, stub->session, addr, sizeof(bp->value));
                if (R_FAILED(res))
                {
                    bp->address = UINT64_MAX;
                    bp->value = 0u;
                    break;
                }
                
                u32 inst = ARMV8_BRK(0u);
                res = svcWriteDebugProcessMemory(stub->session, &inst, bp->address, sizeof(inst));
                if (R_FAILED(res))
                {
                    bp->address = UINT64_MAX;
                    bp->value = 0u;
                    break;
                }

                logf("set sw breakpoint (addr=0x%lX, value=0x%X)\n", bp->address, bp->value);
                bp_set = true;
                break;
            }
        }
    }

    if(bp_set)
    {
        logf("breakpoint set\n");
        gdb_stub_send_packet(stub, "OK");
    }
    else
    {
        gdb_stub_send_error(stub, 0u);
    }

    return true;
}

static bool gdb_stub_pkt_remove_breakpoint(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_remove_breakpoint\n");

    if (length < 4)
    {
        gdb_stub_send_error(stub, 0u);
        return true;
    }

    char type = packet[1];
    u64 addr = strtoul(&packet[3], NULL, 16);

    if (type == '0')
    {
        for (int i = 0; i < MAX_SW_BREAKPOINTS; ++i)
        {
            sw_breakpoint_t* bp = &stub->sw_breakpoints[i];
            if (bp->address == addr)
            {
                logf("removed sw breakpoint (addr=0x%lX, value=0x%X)\n", bp->address, bp->value);
                svcWriteDebugProcessMemory(stub->session, &bp->value, bp->address, sizeof(bp->value));
                bp->address = UINT64_MAX;
                bp->value = 0u;
                break;
            }
        }
    }

    gdb_stub_send_packet(stub, "OK");
    return true;
}

static bool gdb_stub_pkt_read_registers(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_read_registers\n");

    int idx = stub->selected_thread;
    if (idx < 0 || idx >= MAX_THREADS)
    {
        idx = gdb_stub_first_thread_index(stub);
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
    
    if (stub->session == INVALID_HANDLE)
    {
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
    logf("%s\n", __FUNCTION__);
    logf("%s not implemented\n", __FUNCTION__);
    return false;
}

static bool gdb_stub_pkt_write_memory_bin(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    u64 addr, write_len;
    size_t pos = 0u;

    if (stub->session == INVALID_HANDLE)
    {
        return false;
    }

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
    logf("%s\n", __FUNCTION__);

    if (stub->session != INVALID_HANDLE)
    {
        svcContinueDebugEvent(stub->session, 7, NULL, 0u);
    }

    stub->exception_type = UINT32_MAX;
    return true;
}

static bool gdb_stub_pkt_step(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_step\n");

    if (stub->session == INVALID_HANDLE ||
        R_FAILED(svcContinueDebugEvent(stub->session, 7, NULL, 0u)))
    {
        return false;
    }

    return true;
}

static bool gdb_stub_pkt_get_halt_reason(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_get_halt_reason\n");
    gdb_stub_send_stop_reply(stub);
    return true;
}

static bool gdb_stub_pkt_detach(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    uint64_t pid;

    if (packet[1] != '\0')
    {
        if (sscanf(packet, "D;%lx", &pid) == 1 &&
            gdb_stub_detach(stub, pid))
        {
            gdb_stub_send_packet(stub, "OK");
        }
        else
        {
            gdb_stub_send_error(stub, 0u);
        }
    }
    else
    {
        gdb_stub_send_packet(stub, "OK");
    }
    
    return true;
}

static bool gdb_stub_pkt_attach(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    u64 pid;

    if (sscanf(packet, "vAttach;%lx", &pid) != 1)
    {
        gdb_stub_send_error(stub, 0u);
        return true;
    }

    if (gdb_stub_attach(stub, pid))
    {
        svcBreakDebugProcess(stub->session);
    }
    else
    {
        gdb_stub_send_error(stub, 0u);
    }

    return true;
}
