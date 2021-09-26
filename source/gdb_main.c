
#include <stdio.h>
#include <stdlib.h>
#include <switch.h>

#include "gdb_main.h"
#include "gdb_server.h"

#if 0
#define logf(fmt, ...) printf("gdb_main: " fmt, ##__VA_ARGS__)
#else
#define logf(fmt, ...)
#endif

static gdb_server_t* server;

int gdb_main_init(int port)
{
    logf("%s\n", __FUNCTION__);

    server = gdb_server_create(port);
    if(server == NULL)
    {
        return -1;
    }

    return 0;
}

int gdb_main_run(u64 timeout)
{
    Waiter waiters[GDB_MAX_WAITERS];
    ssize_t nwaiters;
    s32 idx;

    nwaiters = gdb_server_waiters(server, waiters, 8);
    if(nwaiters <= 0)
    {
        logf("gdb_server_waiters error\n");
        return -1;
    }

    waitObjects(&idx, waiters, nwaiters, timeout);
    if (idx >= 0)
    {
        if(!gdb_server_handle_event(server, idx))
        {
            return -1;
        }
    }

    return 0;
}

void gdb_main_exit(void)
{
    logf("%s\n", __FUNCTION__);

    if (server != NULL)
    {
        gdb_server_destroy(server);
        server = NULL;
    }
}
