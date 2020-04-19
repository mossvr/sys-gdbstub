
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "gdb_stub_priv.h"


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
    s64 pid, tid;
    char* op = &packet[1];

    if (*op != 'g')
    {
        goto err;
    }

    if (!gdb_stub_parse_thread_id(packet+2, &pid, &tid))
    {
        goto err;
    }

    if ((pid <= 0 && pid != stub->pid) || tid <= 0)
    {
        goto err;
    }

    for (u32 i = 0u; i < MAX_THREADS; ++i)
    {
        if (stub->thread[i].tid != UINT64_MAX &&
            stub->thread[i].tid == (u64)tid)
        {
            stub->selected_thread = i;
            gdb_stub_send_packet(stub, "OK");
            return true;
        }
    }

err:
    gdb_stub_send_error(stub, 0u);
    return true;
}

static bool gdb_stub_pkt_thread_alive(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);
    s64 pid, tid;

    if (!gdb_stub_parse_thread_id(packet+1, &pid, &tid))
    {
        goto err;
    }

    if ((pid <= 0 && pid != stub->pid) || tid <= 0)
    {
        goto err;
    }

    u32 idx = gdb_stub_thread_id_to_index(stub, tid);
    if (idx < MAX_THREADS)
    {
        gdb_stub_send_packet(stub, "OK");
    }

err:
    gdb_stub_send_error(stub, 0u);
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
                gdb_stub_send_error(stub, 0u);
            }

            return true;
        }
        break;
    }

    return false;
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
            return true;
        }
        break;
    }

    return false;
}

static bool gdb_stub_pkt_read_registers(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_read_registers\n");

    u32 idx = stub->selected_thread;

    gdb_stub_packet_begin(stub);

    if(idx >= MAX_THREADS ||
            stub->thread[idx].tid == UINT64_MAX)
    {
        uint8_t zero = 0u;
        for (int i = 0; i < 788; ++i)
        {
            gdb_stub_packet_write_hex_le(stub, &zero, sizeof(zero));
        }
    }
    else
    {
        gdb_stub_packet_write_hex_le(stub, &stub->thread[idx].ctx, 788u);
    }

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
    logf("gdb_stub_pkt_continue\n");

    if (stub->session == INVALID_HANDLE ||
        R_FAILED(svcContinueDebugEvent(stub->session, 0x4u, NULL, 0u)))
    {
        return false;
    }

    stub->exception_type = UINT32_MAX;
    return true;
}

static bool gdb_stub_pkt_step(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("gdb_stub_pkt_step\n");

    if (stub->session == INVALID_HANDLE ||
        R_FAILED(svcContinueDebugEvent(stub->session, 0x4u, NULL, 0u)))
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
    u64 pid;

    if (sscanf(packet, "vAttach;%lx", &pid) != 1)
    {
        gdb_stub_send_error(stub, 0u);
        return true;
    }

    if (gdb_stub_attach(stub, pid))
    {
        gdb_stub_send_stop_reply(stub);
    }
    else
    {
        gdb_stub_send_error(stub, 0u);
    }

    return true;
}
