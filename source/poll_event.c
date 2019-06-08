
#include <string.h>
#include <poll.h>
#include <stdio.h>

#include "poll_event.h"

static void poll_event_thread(void* arg)
{
    poll_event_t* event = (poll_event_t*)arg;

    ueventSignal(&event->done_event);

    while(!event->quit)
    {
        waitSingle(waiterForUEvent(&event->wake_event), UINT64_MAX);
        if(event->quit || event->fds == NULL || event->nfds == 0)
        {
            break;
        }

        event->res = 0;
        ueventClear(&event->done_event);
        printf("poll_event_thread: polling...\n");
        event->res = poll(event->fds, event->nfds, -1);
        ueventSignal(&event->done_event);
    }

    printf("poll_event_thread: exiting...\n");
    event->res = -1;
}

Result poll_event_init(poll_event_t* event)
{
    Result res;

    memset(event, 0, sizeof(*event));
    event->fds = NULL;
    event->nfds = 0;
    event->quit = false;

    ueventCreate(&event->done_event, false);
    ueventCreate(&event->wake_event, true);

    res = threadCreate(&event->t, poll_event_thread, event, 0x1000, 0x2C, -2);
    if(R_FAILED(res))
    {
        printf("poll_event_init: threadCreate failed\n");
        return res;
    }

    res = threadStart(&event->t);

    return res;
}

Waiter poll_event_waiter(poll_event_t* event)
{
    return waiterForUEvent(&event->done_event);
}

int poll_event_result(poll_event_t* event)
{
    return event->res;
}

void poll_event_poll(poll_event_t* event, struct pollfd* fds, size_t nfds)
{
    waitSingle(waiterForUEvent(&event->done_event), UINT64_MAX);
    event->fds = fds;
    event->nfds = nfds;
    ueventSignal(&event->wake_event);
}

void poll_event_destroy(poll_event_t* event)
{
    event->quit = true;
    ueventSignal(&event->wake_event);
    threadWaitForExit(&event->t);
    threadClose(&event->t);
    memset(event, 0, sizeof(*event));
}
