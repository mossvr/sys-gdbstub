

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <switch.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include "gdb_stub_priv.h"

enum
{
    GDB_ERRNO_EPERM = 1,
    GDB_ERRNO_ENOENT = 2,
    GDB_ERRNO_EINTR = 4,
    GDB_ERRNO_EBADF = 9,
    GDB_ERRNO_EACCES = 13,
    GDB_ERRNO_EFAULT = 14,
    GDB_ERRNO_EBUSY = 16,
    GDB_ERRNO_EEXIST = 17,
    GDB_ERRNO_ENODEV = 19,
    GDB_ERRNO_ENOTDIR = 20,
    GDB_ERRNO_EISDIR = 21,
    GDB_ERRNO_EINVAL = 22,
    GDB_ERRNO_ENFILE = 23,
    GDB_ERRNO_EMFILE = 24,
    GDB_ERRNO_EFBIG = 27,
    GDB_ERRNO_ENOSPC = 28,
    GDB_ERRNO_ESPIPE = 29,
    GDB_ERRNO_EROFS = 30,
    GDB_ERRNO_ENAMETOOLONG = 91,
    GDB_ERRNO_EUNKNOWN = 9999
};

typedef struct
{
    const char* op;
    bool (*func)(gdb_stub_t* stub, char* op, char* params, size_t params_len);
} gdb_file_op_handler_t;

static bool gdb_file_open(gdb_stub_t* stub, char* op, char* params, size_t params_len);
static bool gdb_file_close(gdb_stub_t* stub, char* op, char* params, size_t params_len);
static bool gdb_file_pwrite(gdb_stub_t* stub, char* op, char* params, size_t params_len);

static const gdb_file_op_handler_t op_handlers[] =
{
    { "open", gdb_file_open },
    { "close", gdb_file_close },
    { "pwrite", gdb_file_pwrite },
};

char* get_token(char** str, const char* sep)
{
    char* pos = *str;

    int span = strcspn(pos, sep);
    if (span == 0)
        return NULL;

    *str = pos + span;

    if (**str != '\0')
        (*str)++;

    pos[span] = '\0';

    return pos;
}

bool gdb_stub_pkt_file(gdb_stub_t* stub, char* packet, size_t length)
{
    logf("%s\n", __FUNCTION__);

    char* pos = packet;

    char* pkt_type = get_token(&pos, ":");
    if (pkt_type == NULL || strcmp(pkt_type, "vFile") != 0)
        return false;
    
    char* op = get_token(&pos, ":");
    if (op == NULL)
        return false;
    
    char* params = pos;
    size_t params_len = length - ((uintptr_t)params - (uintptr_t)packet);

    for (size_t i = 0u; i < sizeof(op_handlers) / sizeof(op_handlers[0]); ++i)
    {
        if (strcmp(op, op_handlers[i].op) == 0)
        {
            return op_handlers[i].func(stub, op, params, params_len);
        }
    }

    return false;
}

static int translate_errno(int value)
{
    switch (value)
    {
    case EPERM: return GDB_ERRNO_EPERM;
    case ENOENT: return GDB_ERRNO_ENOENT;
    case EINTR: return GDB_ERRNO_EINTR;
    case EBADF: return GDB_ERRNO_EBADF;
    case EACCES: return GDB_ERRNO_EACCES;
    case EFAULT: return GDB_ERRNO_EFAULT;
    case EBUSY: return GDB_ERRNO_EBUSY;
    case EEXIST: return GDB_ERRNO_EEXIST;
    case ENODEV: return GDB_ERRNO_ENODEV;
    case ENOTDIR: return GDB_ERRNO_ENOTDIR;
    case EISDIR: return GDB_ERRNO_EISDIR;
    case EINVAL: return GDB_ERRNO_EINVAL;
    case ENFILE: return GDB_ERRNO_ENFILE;
    case EMFILE: return GDB_ERRNO_EMFILE;
    case EFBIG: return GDB_ERRNO_EFBIG;
    case ENOSPC: return GDB_ERRNO_ENOSPC;
    case ESPIPE: return GDB_ERRNO_ESPIPE;
    case EROFS: return GDB_ERRNO_EROFS;
    case ENAMETOOLONG: return GDB_ERRNO_ENAMETOOLONG;
    }

    return GDB_ERRNO_EUNKNOWN;
}

static void send_result(gdb_stub_t* stub, int res, int errno_value)
{
    char buffer[32];

    if (res < 0)
    {
        snprintf(buffer, sizeof(buffer), "F-1,%x", translate_errno(errno_value));
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "F%x", res);
    }

    logf("file result: %s\n", buffer);
    
    gdb_stub_packet_begin(stub);
    gdb_stub_packet_write_str(stub, buffer);
    gdb_stub_packet_end(stub);
}

static bool gdb_file_open(gdb_stub_t* stub, char* op, char* params, size_t params_len)
{
    logf("%s\n", __FUNCTION__);

    char* pos = params;

    // parse the file name
    char* token = get_token(&pos, ",");
    if (token == NULL)
        return false;

    size_t filename_len = strlen(token);
    if ((filename_len & 1u) != 0u)
        return false;
    filename_len /= 2u;

    if (filename_len >= sizeof(stub->mem))
        return false;

    char* filename = (char*)stub->mem;
    gdb_stub_decode_hex(token, stub->mem, filename_len);
    filename[filename_len] = '\0';

    // parse the flags
    token = get_token(&pos, ",");
    if (token == NULL)
        return false;

    char* end = NULL;
    long flags = strtol(token, &end, 16);
    if (end == token || *end != '\0')
        return false;
    
    // parse the mode
    token = get_token(&pos, ",");
    if (token == NULL)
        return false;
    
    end = NULL;
    long mode = strtol(token, &end, 16);
    if (end == token || *end != '\0')
        return false;

    logf("%s (file=%s, flags=0x%lX, mode=0x%lX)\n", __FUNCTION__, filename, flags, mode);

    // try to find empty slot
    int file_i = -1;
    for (int i = 0; i < MAX_FILES; ++i)
    {
        if (stub->files[i] == -1)
        {
            file_i = i;
            break;
        }
    }

    if (file_i == -1)
    {
        logf("%s: too many files\n", __FUNCTION__);
        send_result(stub, -1, ENFILE);
        return true;
    }

    int fd = open(filename, flags, mode);
    if (fd < 0)
    {
        send_result(stub, -1, errno);
        return true;
    }

    stub->files[file_i] = fd;
    send_result(stub, file_i, 0);
    return true;
}

static bool gdb_file_close(gdb_stub_t* stub, char* op, char* params, size_t params_len)
{
    logf("%s\n", __FUNCTION__);

    char* pos = params;

    char* token = get_token(&pos, ",");
    if (token == NULL)
        return false;
    
    char* end = NULL;
    long file_i = strtol(token, &end, 16);
    if (end == token || *end != '\0')
        return false;
    
    if (file_i < 0 || file_i > MAX_FILES || stub->files[file_i] < 0)
    {
        send_result(stub, -1, EBADF);
        return true;
    }

    int res = close(stub->files[file_i]);
    stub->files[file_i] = -1;

    send_result(stub, res, errno);
    return true;
}

static bool gdb_file_pwrite(gdb_stub_t* stub, char* op, char* params, size_t params_len)
{
    logf("%s\n", __FUNCTION__);

    char* pos = params;

    // parse the fd
    char* token = get_token(&pos, ",");
    if (token == NULL)
        return false;
    
    char* end = NULL;
    long file_i = strtol(token, &end, 16);
    if (end == token || *end != '\0')
        return false;
    
    if (file_i < 0 || file_i > MAX_FILES || stub->files[file_i] < 0)
    {
        send_result(stub, -1, EBADF);
        return true;
    }

    // parse the offset
    token = get_token(&pos, ",");
    if (token == NULL)
        return false;
    
    end = NULL;
    long offset = strtol(token, &end, 16);
    if (end == token || *end != '\0')
        return false;
    
    // get data pointer/size
    char* data = pos;
    intptr_t data_len = (intptr_t)params_len - ((intptr_t)data - (intptr_t)params);
    if (data_len < 0)
        return false;

    logf("%s (fd=%ld, offset=%ld, data_len=%ld)\n", __FUNCTION__, file_i, offset, data_len);

    // we don't have pwrite, so use lseek+write instead
    off_t seek_res = lseek(stub->files[file_i], offset, SEEK_SET);
    if (seek_res < 0)
    {
        send_result(stub, -1, errno);
        return true;
    }

    ssize_t write_res = write(stub->files[file_i], data, data_len);
    send_result(stub, write_res, errno);
    return true;
}
