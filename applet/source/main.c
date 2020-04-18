
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include <switch.h>

#include "error.h"
#include "gdb_server.h"

#if 0
#define logf(fmt, ...) printf("main: " fmt, ##__VA_ARGS__)
#else
#define logf(fmt, ...)
#endif

#define DEBUG 1


#if !DEBUG
// Adjust size as needed.
#define INNER_HEAP_SIZE 0x20000
size_t nx_inner_heap_size = INNER_HEAP_SIZE;
char   nx_inner_heap[INNER_HEAP_SIZE];

void __libnx_initheap(void)
{
	void*  addr = nx_inner_heap;
	size_t size = nx_inner_heap_size;

	// Newlib
	extern char* fake_heap_start;
	extern char* fake_heap_end;

	fake_heap_start = (char*)addr;
	fake_heap_end   = (char*)addr + size;
}

static const SocketInitConfig socket_config = {
    .bsdsockets_version = 1,

    .tcp_tx_buf_size        = 0x1000,
    .tcp_rx_buf_size        = 0x1000,
    .tcp_tx_buf_max_size    = 0,
    .tcp_rx_buf_max_size    = 0,

    .udp_tx_buf_size = 0,
    .udp_rx_buf_size = 0,

    .sb_efficiency = 2,

    .num_bsd_sessions = 3,
    .bsd_service_type = BsdServiceType_Auto,
};
#endif

int main(int argc, char* argv[])
{
    Result res;

#if DEBUG
    res = socketInitializeDefault();
#else
    res = socketInitialize(&socket_config);
#endif
    if (R_FAILED(res))
    {
        return -1;
    }
    int nxlink_fd = -1;

#if DEBUG
    nxlink_fd = nxlinkStdio();
#endif

    gdb_server_t* server;
    Waiter waiters[8];
    ssize_t nwaiters;

    logf("sys-gdbstub init\n");
    server = gdb_server_create(10000);
    if(server == NULL)
    {
        logf("gdb_server_create failed\n");
        return -1;
    }

    logf("sys-gdbstub started\n");
    while(appletMainLoop())
    {
        s32 idx;

        logf("getting waiters from gdb server...\n");
        nwaiters = gdb_server_waiters(server, waiters, 8);
        if(nwaiters <= 0)
        {
            logf("gdb_server_waiters error\n");
            break;
        }
        else
        {
            logf("got %lu waiters\n", nwaiters);
        }


        logf("waiting for an event\n");
        waitObjects(&idx, waiters, nwaiters, 100000000u);
        if (idx >= 0)
        {
            if(!gdb_server_handle_event(server, idx))
            {
                logf("gdb_server_handle_event returned false\n");
                break;
            }
        }

        hidScanInput();
        if (hidKeysDown(CONTROLLER_P1_AUTO) & KEY_PLUS) break;
    }

    logf("exiting\n");
    gdb_server_destroy(server);

    if (nxlink_fd >= 0)
    {
        close(nxlink_fd);
    }
    socketExit();
    return 0;
}
