
#include <stdio.h>
#include <stdint.h>
#include <switch.h>
#include <unistd.h>

#include "gdb_main.h"

#define GDB_PORT 10001
#define ENABLE_NXLINK 0

#if 1
#define logf(fmt, ...) printf("main: " fmt, ##__VA_ARGS__)
#else
#define logf(fmt, ...)
#endif

int main(int argc, char* argv[])
{
    consoleInit(NULL);
    socketInitializeDefault();

#if ENABLE_NXLINK
    int nxlink_fd = -1;
    nxlink_fd = nxlinkStdio();
#endif

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);

    PadState pad;
    padInitializeDefault(&pad);

    bool quit = false;
    logf("sys-gdbstub started\n");
    while (!quit)
    {
        char ip[46];
        gethostname(ip, sizeof(ip));

        if (gdb_main_init(GDB_PORT) != 0)
        {
            break;
        }

        logf("listening on %s:%u\n", ip, GDB_PORT);

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

#if ENABLE_NXLINK
    if (nxlink_fd >= 0)
    {
        close(nxlink_fd);
    }
#endif

    socketExit();
    consoleExit(NULL);
    return 0;
}
