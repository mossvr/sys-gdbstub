
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

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

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

// Init/exit services, update as needed.
void __attribute__((weak)) __appInit(void)
{
    Result rc;

    // Initialize default services.
    rc = smInitialize();
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));

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

    rc = socketInitialize(&socket_config);
    if (R_FAILED(rc))
        fatalThrow(MAKERESULT(Module_SysGdbStub, SysGdbStubError_InitFail_Sockets));
}

void __attribute__((weak)) userAppExit(void);

void __attribute__((weak)) __appExit(void)
{
    // Cleanup default services.
    socketExit();
    smExit();
}

// Main program entrypoint
int main(int argc, char* argv[])
{
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
    while (true)
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
        waitObjects(&idx, waiters, nwaiters, UINT64_MAX);
        if (idx >= 0)
        {
            if(!gdb_server_handle_event(server, idx))
            {
                logf("gdb_server_handle_event returned false\n");
                break;
            }
        }
    }

    logf("exiting\n");
    gdb_server_destroy(server);
    return 0;
}
