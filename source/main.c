
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include <switch.h>

#include "error.h"
#include "gdb_server.h"

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

// Adjust size as needed.
#define INNER_HEAP_SIZE 0x40000
size_t nx_inner_heap_size = INNER_HEAP_SIZE;
char   nx_inner_heap[INNER_HEAP_SIZE];

static int nxlink_sock = -1;

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
    fatalThrow(err);
}

// Init/exit services, update as needed.
void __attribute__((weak)) __appInit(void)
{
    Result rc;

    // Initialize default services.
    rc = smInitialize();
    if (R_FAILED(rc))
        appFatal(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));

    rc = socketInitializeDefault();
    if (R_FAILED(rc))
        appFatal(rc);

    rc = fsInitialize();
    if (R_FAILED(rc))
        appFatal(MAKERESULT(Module_Libnx, LibnxError_InitFail_FS));

    fsdevMountSdmc();

    consoleInit(NULL);

    // redirect stdout & stderr over network to nxlink
    nxlink_sock = nxlinkStdio();
}

void __attribute__((weak)) __appExit(void)
{
    if (nxlink_sock != -1)
    {
        close(nxlink_sock);
        nxlink_sock = -1;
    }

    consoleExit(NULL);

    // Cleanup default services.
    fsdevUnmountAll();
    fsExit();
    socketExit();
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

#if 1
    for(;;)
#else
    while(appletMainLoop())
#endif
    {
        s32 idx;

        printf("getting waiters from gdb server...\n");
        nwaiters = gdb_server_waiters(server, waiters, 8);
        if(nwaiters <= 0)
        {
            printf("gdb_server_waiters error\n");
            break;
        }
        else
        {
            printf("got %lu waiters\n", nwaiters);
        }
        

        printf("waiting for an event\n");
        waitObjects(&idx, waiters, nwaiters, UINT64_MAX);

        if(!gdb_server_handle_event(server, idx))
        {
            printf("gdb_server_handle_event returned false\n");
            break;
        }

#if 0
        hidScanInput();
        if (hidKeysDown(CONTROLLER_P1_AUTO) & KEY_PLUS) break;
        consoleUpdate(NULL);
#endif
    }

    printf("exiting\n");
    gdb_server_destroy(server);

    return 0;
}
