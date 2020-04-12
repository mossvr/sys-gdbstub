
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include <switch.h>

#include "error.h"
#include "gdb_server.h"

int main(int argc, char* argv[])
{
    consoleInit(NULL);
    socketInitializeDefault();
    nxlinkStdio();

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
    while(appletMainLoop())
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

        hidScanInput();
        if (hidKeysDown(CONTROLLER_P1_AUTO) & KEY_PLUS) break;
        consoleUpdate(NULL);
    }

    printf("exiting\n");
    gdb_server_destroy(server);

    socketExit();
    consoleExit(NULL);
    return 0;
}
