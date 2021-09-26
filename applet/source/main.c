
#include <stdio.h>
#include <stdint.h>
#include <switch.h>
#include <unistd.h>

#include "gdb_main.h"

#if 1
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

    consoleInit(NULL);
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);

    PadState pad;
    padInitializeDefault(&pad);

    bool quit = false;
    logf("sys-gdbstub started\n");
    while (!quit)
    {
        if (gdb_main_init() != 0)
        {
            break;
        }

        while(appletMainLoop())
        {
            if (gdb_main_run(100000000u) != 0)
            {
                break;
            }

            padUpdate(&pad);
            u64 kDown = padGetButtonsDown(&pad);

            if (kDown & HidNpadButton_Plus)
            {
                quit = true;
                break;
            }

            consoleUpdate(NULL);
        }

        gdb_main_exit();
    }

    logf("exiting\n");

    if (nxlink_fd >= 0)
    {
        close(nxlink_fd);
    }
    consoleExit(NULL);
    socketExit();
    return 0;
}
