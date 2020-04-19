
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <switch.h>

#include "gdb_stub.h"
#include "svc_dbg.h"

#include "gdb_stub_priv.h"


static const char hex_chars[] = "0123456789abcdef";

static void gdb_stub_send_signal(gdb_stub_t* stub, uint8_t signal);

gdb_stub_t* gdb_stub_create(gdb_stub_output_t output, void* arg)
{
    gdb_stub_t* stub = calloc(1u, sizeof(*stub));
    if(stub == NULL)
    {
        return NULL;
    }

    stub->output = output;
    stub->arg = arg;
    stub->rx.state = CMD_STATE_START;

    stub->session = INVALID_HANDLE;
    stub->pid = UINT64_MAX;
    stub->selected_thread = UINT32_MAX;
    stub->exception_type = UINT32_MAX;

    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        stub->thread[i].tid = UINT64_MAX;
    }

    return stub;
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

int gdb_stub_decode_hex(const char* input, size_t input_len, void* output, size_t output_len)
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

bool gdb_stub_parse_thread_id(const char* input, s64* o_pid, s64* o_tid)
{
    char* end;
    
    if (*input == 'p')
    {
        input++;
        *o_pid = strtol(input, &end, 16);
        if (end == input || *end != '.')
        {
            return false;
        }
        input = end+1;
    }
    else
    {
        *o_pid = 0;
    }

    *o_tid = strtol(input, &end, 16);
    return end != input;
}

void gdb_stub_putc(gdb_stub_t* stub, char c)
{
    stub->output(stub, &c, 1u, stub->arg);
}

void gdb_stub_packet_begin(gdb_stub_t* stub)
{
    stub->tx.state = CMD_STATE_DATA;
    stub->tx.checksum = 0u;
    stub->tx.pos = 0u;

    stub->tx.cache[stub->tx.pos++] = '$';
}

bool gdb_stub_packet_write(gdb_stub_t* stub, const char* data, size_t len)
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

bool gdb_stub_packet_write_hex_le(gdb_stub_t* stub, const void* data, size_t data_len)
{
    for(uint32_t i = 0u; i != data_len; ++i)
    {
        gdb_stub_packet_write(stub, &hex_chars[(((uint8_t*)data)[i] >> 4u) & 0xFu], 1u);
        gdb_stub_packet_write(stub, &hex_chars[((uint8_t*)data)[i] & 0xFu], 1u);
    }

    return true;
}

bool gdb_stub_packet_write_hex_be(gdb_stub_t* stub, const void* data, size_t data_len)
{
    for(uint32_t i = data_len; i != 0u; --i)
    {
        gdb_stub_packet_write(stub, &hex_chars[(((uint8_t*)data)[i-1u] >> 4u) & 0xFu], 1u);
        gdb_stub_packet_write(stub, &hex_chars[((uint8_t*)data)[i-1u] & 0xFu], 1u);
    }

    return true;
}

bool gdb_stub_packet_end(gdb_stub_t* stub)
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

void gdb_stub_send_packet(gdb_stub_t* stub, const char* packet)
{
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, packet, strlen(packet));
    gdb_stub_packet_end(stub);
}

void gdb_stub_send_error(gdb_stub_t* stub, uint8_t err)
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
    gdb_stub_packet_write(stub, ":", 1u);
    gdb_stub_packet_end(stub);
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
            if (stub->session != INVALID_HANDLE)
            {
                svcBreakDebugProcess(stub->session);
            }
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
    if (stub->session != INVALID_HANDLE)
    {
        svcCloseHandle(stub->session);
        stub->session = INVALID_HANDLE;
    }
    memset(stub, 0, sizeof(*stub));
    free(stub);
}

bool gdb_stub_get_waiter(gdb_stub_t* stub, Waiter* waiter)
{
    if(stub->session != INVALID_HANDLE)
    {
        *waiter = waiterForHandle(stub->session);
        return true;
    }

    return false;
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

void gdb_stub_send_stop_reply(gdb_stub_t* stub)
{
    if (stub->session == INVALID_HANDLE)
    {
        uint8_t res = 0;
        gdb_stub_packet_begin(stub);
        gdb_stub_packet_write(stub, "W", 1u);
        gdb_stub_packet_write_hex_be(stub, &res, sizeof(res));
        gdb_stub_packet_end(stub);
        return;
    }

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

static uint64_t find_main_base(gdb_stub_t* stub)
{
    Result res;
    MemoryInfo mem_info;
    uint32_t dummy;
    uint64_t addr = 0u;
    bool done = false;
    uint32_t module_count = 0u;
    uint64_t base = 0u;

    do
    {
        res = svcQueryDebugProcessMemory(&mem_info, &dummy, stub->session, addr);
        if (R_FAILED(res))
        {
            logf("svcQueryDebugProcessMemory failed\n");
            break;
        }

        if (mem_info.type == MemType_CodeStatic &&
            mem_info.perm == Perm_Rx)
        {
            uint32_t offset;
            module_header_t module;

            res = svcReadDebugProcessMemory(&offset, stub->session, mem_info.addr + 4u, sizeof(offset));
            if (R_FAILED(res))
            {
                logf("svcReadDebugProcessMemory failed\n");
                break;
            }

            res = svcReadDebugProcessMemory(&module, stub->session, mem_info.addr + offset, sizeof(module));
            if (R_FAILED(res))
            {
                logf("svcReadDebugProcessMemory failed\n");
                break;
            }

            if (module.magic == MOD0_MAGIC)
            {
                logf("found module at addr 0x%lX\n", mem_info.addr);
                base = addr;
                module_count++;
                if (module_count == 2u)
                {
                    break;
                }
            }
        }

        done = mem_info.addr + mem_info.size <= addr;
        addr = mem_info.addr + mem_info.size;
    } while (!done);
    
    return base;
}

bool gdb_stub_attach(gdb_stub_t* stub, u64 pid)
{
    if (stub->session != INVALID_HANDLE)
    {
        return false;
    }

    logf("attaching to %lu\n", pid);
    if(R_FAILED(svcDebugActiveProcess(&stub->session, pid)))
    {
        logf("svcDebugActiveProcess failed\n");
        stub->session = INVALID_HANDLE;
        stub->pid = UINT64_MAX;
        return false;
    }

    stub->pid = pid;
    stub->base_addr = find_main_base(stub);

    return true;
}

bool gdb_stub_detach(gdb_stub_t* stub, u64 pid)
{
    if (stub->session == INVALID_HANDLE ||
        pid != stub->pid)
    {
        return false;
    }

    svcCloseHandle(stub->session);
    stub->session = INVALID_HANDLE;
    stub->pid = UINT64_MAX;
    stub->base_addr = 0u;

    for (uint32_t i = 0u; i < MAX_THREADS; ++i)
    {
        stub->thread[i].tid = UINT64_MAX;
    }

    return true;
}

static void gdb_stub_exception(gdb_stub_t* stub, const debug_exception_t* exception)
{
    stub->exception_type = exception->type;
    
    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        if(stub->thread[i].tid != UINT64_MAX)
        {
            svcGetDebugThreadContext(&stub->thread[i].ctx, stub->session, stub->thread[i].tid, RegisterGroup_All);
        }
    }

    gdb_stub_send_stop_reply(stub);
}

u32 gdb_stub_thread_id_to_index(gdb_stub_t* stub, u64 tid)
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

static void gdb_stub_attach_thread(gdb_stub_t* stub, u64 thread_id)
{
    u32 thread_idx = gdb_stub_thread_id_to_index(stub, thread_id);

    // if it's a new thread, find a slot for it
    if (thread_idx == UINT32_MAX)
    {
        for(u32 i = 0u; i < MAX_THREADS; ++i)
        {
            if(stub->thread[i].tid == UINT64_MAX)
            {
                thread_idx = i;
                break;
            }
        }

        // check if we've exceeded max threads
        if (thread_idx == UINT32_MAX)
        {
            logf("exceeded max threads\n");
            return;
        }

        stub->thread[thread_idx].tid = thread_id;
        logf("thread %lu attached (idx=%u)\n", thread_id, thread_idx);
    }

    svcGetDebugThreadContext(&stub->thread[thread_idx].ctx, stub->session, thread_id, RegisterGroup_All);
}

static void gdb_stub_exit_thread(gdb_stub_t* stub, u64 thread_id)
{
    u32 idx = gdb_stub_thread_id_to_index(stub, thread_id);
    if (idx < MAX_THREADS)
    {
        logf("thread %lu detached\n", thread_id);
        memset(&stub->thread[idx], 0, sizeof(stub->thread[idx]));
        stub->thread[idx].tid = UINT64_MAX;
    }
}

static void gdb_stub_event(gdb_stub_t* stub, u64 pid, const debug_event_t* event)
{
    print_debug_event(&stub->event);

    switch(event->type)
    {
    case DEBUG_EVENT_ATTACH_PROCESS:
        break;
    case DEBUG_EVENT_ATTACH_THREAD:
        gdb_stub_attach_thread(stub, event->thread_id);
        break;
    case DEBUG_EVENT_EXIT_PROCESS:
        gdb_stub_detach(stub, pid);
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
        gdb_stub_event(stub, stub->pid, &stub->event);
    }
}
