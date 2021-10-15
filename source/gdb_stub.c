
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include <switch.h>

#include "gdb_stub.h"
#include "svc_dbg.h"

#include "gdb_stub_priv.h"


static const char hex_chars[] = "0123456789abcdef";

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
    stub->pid = -1;
    stub->selected_thread = -1;
    stub->exception_type = UINT32_MAX;

    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        stub->thread[i].tid = -1;
    }

    for (int i = 0; i < MAX_SW_BREAKPOINTS; ++i)
    {
        stub->sw_breakpoints[i].address = 0u;
    }

    stub->step_bp[0].address = 0u;
    stub->step_bp[1].address = 0u;

    for (int i = 0; i < MAX_MODULES; ++i)
    {
        stub->modules[i] = UINT64_MAX;
    }

    for (int i = 0; i < MAX_FILES; ++i)
    {
        stub->files[i] = -1;
    }

    return stub;
}

static char* gdb_stub_decode_hex_char(char* str, uint8_t* out)
{
    char c = *str;

    if ((c >= 'a') && (c <= 'f'))
    {
        *out = (*out & ~0xF) | (c - 'a' + 10);
        str++;
    }
    else if ((c >= '0') && (c <= '9'))
    {
        *out = (*out & ~0xF) | (c - '0');
        str++;
    }
    else if ((c >= 'A') && (c <= 'F'))
    {
        *out = (*out & ~0xF) | (c - 'A' + 10);
        str++;
    }

    return str;
}

static char* gdb_stub_decode_hex_byte(char* str, uint8_t* out)
{
    str = gdb_stub_decode_hex_char(str, out);
    *out <<= 4u;
    str = gdb_stub_decode_hex_char(str, out);
    return str;
}

char* gdb_stub_decode_hex(char* str, void* buffer, size_t len)
{
    uint8_t* u8 = buffer;

    while (len != 0u)
    {
        str = gdb_stub_decode_hex_byte(str, u8);
        u8++;
        len--;
    }

    return str;
}

bool gdb_stub_parse_thread_id(const char* input, int* o_pid, int* o_tid)
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
    if (stub->tx.state != CMD_STATE_START)
    {
        logf("%s: already building a packet\n", __FUNCTION__);
        return;
    }

    stub->tx.state = CMD_STATE_DATA;
    stub->tx.checksum = 0u;
    stub->tx.pos = 0u;

    stub->tx.buffer[stub->tx.pos++] = '$';
}

void gdb_stub_packet_write(gdb_stub_t* stub, const char* data, size_t len)
{
    if(stub->tx.state != CMD_STATE_DATA)
    {
        return;
    }

    while(len != 0u)
    {
        char c = *data;

        // flush the tx buffer if it's full
        if(stub->tx.pos + 2u > sizeof(stub->tx.buffer))
        {
            stub->output(stub, stub->tx.buffer, stub->tx.pos, stub->arg);
            stub->tx.pos = 0u;
        }

        // escape reserved values
        if(c == '$' || c == '#' || c == '}' || c == '*')
        {
            stub->tx.buffer[stub->tx.pos++] = '}';
            stub->tx.checksum += '}';
            c ^= 0x20;
        }

        stub->tx.buffer[stub->tx.pos++] = c;
        stub->tx.checksum += c;
        data++;
        len--;
    }
}

void gdb_stub_packet_write_hex_le(gdb_stub_t* stub, const void* data, size_t data_len)
{
    for(uint32_t i = 0u; i != data_len; ++i)
    {
        gdb_stub_packet_write(stub, &hex_chars[(((uint8_t*)data)[i] >> 4u) & 0xFu], 1u);
        gdb_stub_packet_write(stub, &hex_chars[((uint8_t*)data)[i] & 0xFu], 1u);
    }
}

void gdb_stub_packet_write_hex_be(gdb_stub_t* stub, const void* data, size_t data_len)
{
    for(uint32_t i = data_len; i != 0u; --i)
    {
        gdb_stub_packet_write(stub, &hex_chars[(((uint8_t*)data)[i-1u] >> 4u) & 0xFu], 1u);
        gdb_stub_packet_write(stub, &hex_chars[((uint8_t*)data)[i-1u] & 0xFu], 1u);
    }
}

void gdb_stub_packet_write_str(gdb_stub_t* stub, const void* str)
{
    gdb_stub_packet_write(stub, str, strlen(str));
}

void gdb_stub_packet_write_thread_id(gdb_stub_t* stub, int pid, int tid)
{
    char* buf = (char*)stub->mem;
    size_t buf_len = sizeof(stub->mem);

    gdb_stub_packet_write_str(stub, "p");

    if (pid < 0)
    {
        snprintf(buf, buf_len, "-%lx.", (long unsigned int)(pid * -1));
    }
    else
    {
        snprintf(buf, buf_len, "%lx.", (long unsigned int)pid);
    }

    gdb_stub_packet_write_str(stub, buf);

    if (tid < 0)
    {
        snprintf(buf, buf_len, "-%lx", (long unsigned int)(tid * -1));
    }
    else
    {
        snprintf(buf, buf_len, "%lx", (long unsigned int)tid);
    }

    gdb_stub_packet_write_str(stub, buf);
}

void gdb_stub_packet_end(gdb_stub_t* stub)
{
    if(stub->tx.state != CMD_STATE_DATA)
    {
        return;
    }

    // flush the tx buffer if it's full
    if(stub->tx.pos + 3u > sizeof(stub->tx.buffer))
    {
        stub->output(stub, stub->tx.buffer, stub->tx.pos, stub->arg);
        stub->tx.pos = 0u;
    }

    stub->tx.buffer[stub->tx.pos++] = '#';
    stub->tx.buffer[stub->tx.pos++] = hex_chars[(stub->tx.checksum >> 4u) & 0xFu];
    stub->tx.buffer[stub->tx.pos++] = hex_chars[stub->tx.checksum & 0xFu];

    // send the rest of the packet
    stub->output(stub, stub->tx.buffer, stub->tx.pos, stub->arg);
    stub->tx.pos = 0u;
    stub->tx.state = CMD_STATE_START;

}

void gdb_stub_send_packet(gdb_stub_t* stub, const char* packet)
{
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, packet, strlen(packet));
    gdb_stub_packet_end(stub);
}

void gdb_stub_send_error(gdb_stub_t* stub, uint8_t err)
{
    logf("%s (err=0x%X)\n", __FUNCTION__, err);
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, "E", 1u);
    gdb_stub_packet_write_hex_le(stub, &err, sizeof(err));
    gdb_stub_packet_end(stub);
}

static void gdb_stub_send_signal(gdb_stub_t* stub, uint8_t signal)
{
    logf("%s (signal=%u, thread=%d)\n", __FUNCTION__, signal, stub->selected_thread);
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write(stub, "T", 1u);
    gdb_stub_packet_write_hex_le(stub, &signal, sizeof(signal));
    
    if (stub->selected_thread >= 0)
    {
        gdb_stub_packet_write_str(stub, "thread:");
        gdb_stub_packet_write_thread_id(stub, stub->pid, stub->thread[stub->selected_thread].tid);
    }
    gdb_stub_packet_write_str(stub, ";");

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
            gdb_stub_send_packet(stub, "OK");
            if (stub->session != INVALID_HANDLE)
            {
                svcBreakDebugProcess(stub->session);
            }
            else
            {
                gdb_stub_send_stop_reply(stub);
            }
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
        else if(stub->rx.pos < sizeof(stub->rx.packet)-1u)
        {
            stub->rx.packet[stub->rx.pos++] = c;
            stub->rx.checksum += (uint8_t)c;
        }
        else
        {
            // buffer too small
            stub->rx.state = CMD_STATE_START;
            gdb_stub_send_error(stub, 0);
            logf("packet too large\n");
        }
        break;
    case CMD_STATE_ESC:
        if(stub->rx.pos < sizeof(stub->rx.packet)-1u)
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
            logf("packet too large\n");
        }
        break;
    case CMD_STATE_CHECKSUM:
        stub->rx.checksum_buf[stub->rx.checksum_pos++] = c;

        if(stub->rx.checksum_pos == 2u)
        {
            uint8_t checksum = 0u;
            gdb_stub_decode_hex(stub->rx.checksum_buf, &checksum, sizeof(checksum));

            if (checksum == stub->rx.checksum)
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
    if (stub->pid >= 0)
    {
        gdb_stub_detach(stub, stub->pid);
    }

    // close all files
    for (int i = 0; i < MAX_FILES; ++i)
    {
        if (stub->files[i] != -1)
        {
            close(stub->files[i]);
            stub->files[i] = -1;
        }
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

    uint8_t signal = 0u;

    switch(stub->exception_type)
    {
    case DEBUG_EXCEPTION_TRAP:
        signal = 5u;
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
        signal = 5u;
        break;
    case DEBUG_EXCEPTION_USER_BREAK:
        break;
    case DEBUG_EXCEPTION_DEBUGGER_BREAK:
        signal = 2u;
        break;
    case DEBUG_EXCEPTION_BAD_SVC_ID:
        break;
    case DEBUG_EXCEPTION_SERROR:
        break;
    }

    gdb_stub_send_signal(stub, signal);
}

bool gdb_stub_read_module_header(gdb_stub_t* stub, uint64_t addr, module_header_t* header)
{
    Result res;
    uint32_t offset;

    if (stub->session == INVALID_HANDLE)
    {
        return false;
    }

    res = svcReadDebugProcessMemory(&offset, stub->session, addr + 4u, sizeof(offset));
    if (R_FAILED(res))
    {
        return false;
    }

    res = svcReadDebugProcessMemory(header, stub->session, addr + offset, sizeof(*header));
    if (R_FAILED(res))
    {
        return false;
    }

    if (header->magic == MOD0_MAGIC)
    {
        return true;
    }

    return false;
}

static void find_modules(gdb_stub_t* stub)
{
    Result res;
    MemoryInfo mem_info;
    uint32_t dummy;
    uint64_t addr = 0u;
    bool done = false;
    size_t i = 0u;

    do
    {
        res = svcQueryDebugProcessMemory(&mem_info, &dummy, stub->session, addr);
        if (R_FAILED(res))
        {
            logf("svcQueryDebugProcessMemory failed\n");
            break;
        }

        if ((mem_info.type == MemType_CodeStatic ||
                mem_info.type == MemType_ModuleCodeStatic) &&
            mem_info.perm == Perm_Rx)
        {
            module_header_t module;

            if (gdb_stub_read_module_header(stub, mem_info.addr, &module))
            {
                logf("found module at addr 0x%lX\n", mem_info.addr);
                stub->modules[i++] = mem_info.addr;
                if (i == MAX_MODULES)
                {
                    break;
                }
            }
        }

        done = mem_info.addr + mem_info.size <= addr;
        addr = mem_info.addr + mem_info.size;
    } while (!done);
}

static uint64_t find_main_base(gdb_stub_t* stub)
{
    uint32_t module_count = 0u;
    uint64_t base = 0u;

    for (int i = 0; i < MAX_MODULES; ++i)
    {
        if (stub->modules[i] != UINT64_MAX)
        {
            module_count++;
            base = stub->modules[i];

            // main is first if it's alone, otherwise it's second after rtld
            if (module_count == 2u)
            {
                break;
            }
        }
    }

    return base;
}

bool gdb_stub_attach(gdb_stub_t* stub, int pid)
{
    if (stub->session != INVALID_HANDLE || pid < 0)
    {
        return false;
    }

    logf("attaching to %d\n", pid);
    if(R_FAILED(svcDebugActiveProcess(&stub->session, (u64)pid)))
    {
        logf("svcDebugActiveProcess failed\n");
        stub->session = INVALID_HANDLE;
        stub->pid = -1;
        return false;
    }

    stub->pid = pid;
    find_modules(stub);
    stub->base_addr = find_main_base(stub);

    return true;
}

bool gdb_stub_detach(gdb_stub_t* stub, int pid)
{
    if (stub->session == INVALID_HANDLE ||
        pid != stub->pid)
    {
        return false;
    }

    // remove software breakpoints
    for (int i = 0; i < MAX_SW_BREAKPOINTS; ++i)
    {
        stub->sw_breakpoints[i].address = 0u;
    }

    // remove step breakpoints
    stub->step_bp[0].address = 0u;
    stub->step_bp[1].address = 0u;

    // remove modules
    for (int i = 0; i < MAX_MODULES; ++i)
    {
        stub->modules[i] = UINT64_MAX;
    }

    svcCloseHandle(stub->session);
    stub->session = INVALID_HANDLE;
    stub->pid = -1;
    stub->selected_thread = -1;
    stub->base_addr = 0u;

    for (uint32_t i = 0u; i < MAX_THREADS; ++i)
    {
        stub->thread[i].tid = -1;
    }

    return true;
}

static void enable_bp(gdb_stub_t* stub, sw_breakpoint_t* bp)
{
    if (bp->address != 0u)
    {
        svcReadDebugProcessMemory(&bp->value, stub->session, bp->address, sizeof(bp->value));

        uint32_t inst = ARMV8_BRK(0u);
        svcWriteDebugProcessMemory(stub->session, &inst, bp->address, sizeof(inst));
    }
}

void gdb_stub_enable_breakpoints(gdb_stub_t* stub)
{
    for (int i = 0; i < MAX_SW_BREAKPOINTS; ++i)
    {
        enable_bp(stub, &stub->sw_breakpoints[i]);
    }

    enable_bp(stub, &stub->step_bp[0]);
    enable_bp(stub, &stub->step_bp[1]);
}

static void disable_bp(gdb_stub_t* stub, sw_breakpoint_t* bp)
{
    if (bp->address != 0u)
    {
        svcWriteDebugProcessMemory(stub->session, &bp->value, bp->address, sizeof(bp->value));
    }
}

void gdb_stub_disable_breakpoints(gdb_stub_t* stub)
{
    for (int i = 0; i < MAX_SW_BREAKPOINTS; ++i)
    {
        disable_bp(stub, &stub->sw_breakpoints[i]);
    }

    disable_bp(stub, &stub->step_bp[0]);
    disable_bp(stub, &stub->step_bp[1]);
}

static void gdb_stub_exception(gdb_stub_t* stub, int tid, const debug_exception_t* exception)
{
    stub->exception_type = exception->type;
    gdb_stub_disable_breakpoints(stub);

    // clear step breakpoints
    stub->step_bp[0].address = 0u;
    stub->step_bp[1].address = 0u;

    int idx = gdb_stub_thread_id_to_index(stub, tid);
    if (idx < MAX_THREADS)
    {
        stub->selected_thread = idx;
    }
    else
    {
        stub->selected_thread = gdb_stub_first_thread_index(stub);
    }
    logf("selected thread %d\n", stub->selected_thread);
    
    for(u32 i = 0u; i < MAX_THREADS; ++i)
    {
        if(stub->thread[i].tid >= 0)
        {
            svcGetDebugThreadContext(&stub->thread[i].ctx, stub->session, (u64)stub->thread[i].tid, RegisterGroup_All);
        }
    }

    gdb_stub_send_stop_reply(stub);
}

int gdb_stub_first_thread_index(gdb_stub_t* stub)
{
    for(int i = 0; i < MAX_THREADS; ++i)
    {
        if(stub->thread[i].tid >= 0)
        {
            return i;
        }
    }

    return -1;
}

int gdb_stub_thread_id_to_index(gdb_stub_t* stub, int tid)
{
    for (int i = 0; i < MAX_THREADS; ++i)
    {
        if (stub->thread[i].tid == tid)
        {
            return i;
        }
    }

    return -1;
}

static void gdb_stub_attach_thread(gdb_stub_t* stub, int thread_id)
{
    int thread_idx = gdb_stub_thread_id_to_index(stub, thread_id);

    // if it's a new thread, find a slot for it
    if (thread_idx < 0)
    {
        for (int i = 0; i < MAX_THREADS; ++i)
        {
            if (stub->thread[i].tid < 0)
            {
                thread_idx = i;
                break;
            }
        }

        // check if we've exceeded max threads
        if (thread_idx < 0)
        {
            logf("exceeded max threads\n");
            return;
        }

        stub->thread[thread_idx].tid = thread_id;
        logf("thread %d attached (idx=%d)\n", thread_id, thread_idx);
    }

    svcGetDebugThreadContext(&stub->thread[thread_idx].ctx, stub->session, (u64)thread_id, RegisterGroup_All);
}

static void gdb_stub_exit_thread(gdb_stub_t* stub, int thread_id)
{
    int idx = gdb_stub_thread_id_to_index(stub, thread_id);
    if (idx < MAX_THREADS)
    {
        logf("thread %d detached\n", thread_id);
        memset(&stub->thread[idx], 0, sizeof(stub->thread[idx]));
        stub->thread[idx].tid = -1;
    }
}

static void gdb_stub_event(gdb_stub_t* stub, int pid, const debug_event_t* event)
{
    print_debug_event(&stub->event);

    switch(event->type)
    {
    case DEBUG_EVENT_ATTACH_PROCESS:
        break;
    case DEBUG_EVENT_ATTACH_THREAD:
        gdb_stub_attach_thread(stub, (int)event->thread_id);
        break;
    case DEBUG_EVENT_EXIT_PROCESS:
        gdb_stub_detach(stub, pid);
        gdb_stub_send_stop_reply(stub);
        break;
    case DEBUG_EVENT_EXIT_THREAD:
        gdb_stub_exit_thread(stub, (int)event->thread_id);
        break;
    case DEBUG_EVENT_EXCEPTION:
        gdb_stub_exception(stub, (int)event->thread_id, &event->exception);
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
