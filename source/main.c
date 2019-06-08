
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <twili.h>
#include <poll.h>
#include <unistd.h>

#include <switch.h>

#include "error.h"
#include "gdb_server.h"

static const SocketInitConfig socket_config = {
    .bsdsockets_version = 1,

    .tcp_tx_buf_size        = 0x2000,
    .tcp_rx_buf_size        = 0x2000,
    .tcp_tx_buf_max_size    = 0x4000,
    .tcp_rx_buf_max_size    = 0x4000,

    .udp_tx_buf_size = 0,
    .udp_rx_buf_size = 0,

    .sb_efficiency = 2,

    .serialized_out_addrinfos_max_size  = 0x1000,
    .serialized_out_hostent_max_size    = 0x200,
    .bypass_nsd                         = false,
    .dns_timeout                        = 0,
};

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

// Adjust size as needed.
#define INNER_HEAP_SIZE 0x40000
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

static void appFatal(Result err)
{
    printf("fatal error: 0x%X (%d-%d)\n", err, R_MODULE(err), R_DESCRIPTION(err));
    fatalSimple(err);
}

// Init/exit services, update as needed.
void __attribute__((weak)) __appInit(void)
{
    Result rc;

    // Initialize default services.
    rc = smInitialize();
    if (R_FAILED(rc))
        appFatal(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));

    rc = twiliInitialize();
    if (R_FAILED(rc))
        appFatal(rc);

    // Enable this if you want to use HID.
    /*rc = hidInitialize();
    if (R_FAILED(rc))
        fatalSimple(MAKERESULT(Module_Libnx, LibnxError_InitFail_HID));*/

    //Enable this if you want to use time.
    /*rc = timeInitialize();
    if (R_FAILED(rc))
        fatalSimple(MAKERESULT(Module_Libnx, LibnxError_InitFail_Time));

    __libnx_init_time();*/

    rc = socketInitialize(&socket_config);
    if (R_FAILED(rc))
        appFatal(rc);

    rc = fsInitialize();
    if (R_FAILED(rc))
        appFatal(MAKERESULT(Module_Libnx, LibnxError_InitFail_FS));

    fsdevMountSdmc();
}

void __attribute__((weak)) __appExit(void)
{
    // Cleanup default services.
    fsdevUnmountAll();
    fsExit();
    socketExit();
    //timeExit();//Enable this if you want to use time.
    //hidExit();// Enable this if you want to use HID.
    twiliExit();
    smExit();
}

int main(int argc, char* argv[])
{
    gdb_server_t* server;
    Waiter waiters[8];
    ssize_t nwaiters;

    printf("sys-gdbstub init\n");
    server = gdb_server_create(10000);
    if(server == NULL)
    {
        printf("gdb_server_create failed\n");
        return -1;
    }

    printf("sys-gdbstub started\n");

    for(;;)
    {
        s32 idx;

        nwaiters = gdb_server_waiters(server, waiters, 8);
        if(nwaiters <= 0)
        {
            printf("gdb_server_waiters error\n");
            break;
        }

        waitObjects(&idx, waiters, nwaiters, UINT64_MAX);

        if(!gdb_server_handle_event(server, idx))
        {
            break;
        }
    }

    printf("exiting\n");
    gdb_server_destroy(server);

    return 0;
}
