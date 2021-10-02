
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <switch.h>

#include "gdb_stub_priv.h"

typedef struct
{
    const char* cmd;
    void (*func)(gdb_stub_t* stub, int argc, char** argv);
    const char* desc;
} gdb_rcmd_handler_t;

static void gdb_rcmd_help(gdb_stub_t* stub, int argc, char** argv);
static void gdb_rcmd_memory(gdb_stub_t* stub, int argc, char** argv);
static void gdb_rcmd_modules(gdb_stub_t* stub, int argc, char** argv);

static const gdb_rcmd_handler_t rcmd_handler[] =
{
    { "help", gdb_rcmd_help, "List monitor commands" },
    { "memory", gdb_rcmd_memory, "List mapped memory regions" },
    { "modules", gdb_rcmd_modules, "List program modules" },
};

bool gdb_stub_query_rcmd(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);

    // skip to ,
    char* pos = packet;
    while (*pos != ',' && *pos != '\0')
        pos++;

    if (*pos != ',')
        return false;

    pos++;
    length -= (pos - packet);

    // decode command string from hex
    char command[128];
    size_t count = length / 2u;
    if (count > sizeof(command) - 1u)
        return false;

    gdb_stub_decode_hex(pos, command, count);
    command[count] = '\0';

    // split command into argument array
    char* argv[16];
    int argc = 0;

    argv[argc] = strtok(command, " ");
    while (argv[argc] != NULL)
    {
        if (argc == sizeof(argv) / sizeof(argv[0]))
            return false;

        argv[++argc] = strtok(NULL, " ");
    }

    if (argc == 0)
    {
        snprintf(command, sizeof(command), "%s", "help");
        argv[0] = command;
        argv[1] = NULL;
        argc = 1;
        gdb_stub_packet_begin(stub);
        gdb_rcmd_help(stub, argc, argv);
        gdb_stub_packet_end(stub);
    }

    // call the command function
    for (size_t i = 0u; i < sizeof(rcmd_handler) / sizeof(rcmd_handler[0]); ++i)
    {
        if (strcmp(argv[0], rcmd_handler[i].cmd) == 0)
        {
            gdb_stub_packet_begin(stub);
            rcmd_handler[i].func(stub, argc, argv);
            gdb_stub_packet_end(stub);

            return true;
        }
    }

    return false;
}

static void rcmd_printf(gdb_stub_t* stub, const char* fmt, ...)
{
    char* buffer = (char*)stub->mem;
    size_t buffer_size = sizeof(stub->mem);

    va_list arglist;
    va_start(arglist, fmt);
    int len = vsnprintf(buffer, buffer_size, fmt, arglist);
    va_end(arglist);

    if (len > buffer_size)
        len = buffer_size - 1u;

    gdb_stub_packet_write_hex_le(stub, buffer, len);
}

static void rcmd_write_hex(gdb_stub_t* stub, const void* data, size_t len)
{
    static const char hex_chars[] = "0123456789abcdef";
    const uint8_t* byte = data;

    while (len != 0u)
    {
        rcmd_printf(stub, "%c%c",
            hex_chars[(*byte >> 4u) & 0xFu],
            hex_chars[*byte & 0xFu]);
        len--;
        byte++;
    }
}

static void gdb_rcmd_help(gdb_stub_t* stub, int argc, char** argv)
{
    for (size_t i = 0u; i < sizeof(rcmd_handler) / sizeof(rcmd_handler[0]); ++i)
    {
        rcmd_printf(stub, "  %-20s%s\n", rcmd_handler[i].cmd, rcmd_handler[i].desc);
    }
}

static void gdb_rcmd_memory(gdb_stub_t* stub, int argc, char** argv)
{
    Result res;
    MemoryInfo mem_info;
    uint32_t dummy;
    uint64_t addr = 0u;
    bool done = false;

    rcmd_printf(stub, "memory:\n");

    do
    {
        res = svcQueryDebugProcessMemory(&mem_info, &dummy, stub->session, addr);
        if (R_FAILED(res))
            break;

        rcmd_printf(stub, "  - addr: 0x%lx\n", mem_info.addr);
        rcmd_printf(stub, "    size: 0x%lx\n", mem_info.size);
        rcmd_printf(stub, "    type: 0x%x\n", mem_info.type);
        rcmd_printf(stub, "    attr: 0x%x\n", mem_info.attr);
        rcmd_printf(stub, "    perm: 0x%x\n", mem_info.perm);

        done = mem_info.addr + mem_info.size <= addr;
        addr = mem_info.addr + mem_info.size;
    } while (!done);
}

static void gdb_rcmd_modules(gdb_stub_t* stub, int argc, char** argv)
{
    rcmd_printf(stub, "modules:\n");

    if (stub->pid == -1)
        return;

    LoaderModuleInfo modules[16];
    s32 module_count = 0;
    Result res = ldrDmntGetProcessModuleInfo((u64)stub->pid, modules, sizeof(modules) / sizeof(modules[0]), &module_count);
    if (R_FAILED(res))
        module_count = 0;
    
    for (s32 i = 0; i < module_count; ++i)
    {
        rcmd_printf(stub, "  - build_id: \"");
        rcmd_write_hex(stub, modules[i].build_id, sizeof(modules[i].build_id));
        rcmd_printf(stub, "\"\n");
        rcmd_printf(stub, "    address: 0x%llx\n", modules[i].base_address);
        rcmd_printf(stub, "    size: 0x%llx\n", modules[i].size);
    }
}
