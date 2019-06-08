
#include <string.h>
#include <poll.h>
#include <stdio.h>

#include "poll_thread.h"

static void poll_thread(void* arg)
{
    poll_thread_t* thread = (poll_thread_t*)arg;

    ueventSignal(&thread->done_event);

    while(!thread->quit)
    {
        waitSingle(waiterForUEvent(&thread->wake_event), UINT64_MAX);
        if(thread->quit || thread->fds == NULL || thread->nfds == 0)
        {
            break;
        }

        thread->res = 0;
        ueventClear(&thread->done_event);
        printf("poll_thread_thread: polling [ ");
        for(size_t i = 0u; i < thread->nfds; ++i)
        {
            printf("%d ", thread->fds[i].fd);
        }
        printf("]\n");
        thread->res = poll(thread->fds, thread->nfds, thread->timeout);
        ueventSignal(&thread->done_event);
    }

    printf("poll_thread_thread: exiting...\n");
    thread->res = -1;
}

Result poll_thread_init(poll_thread_t* thread)
{
    Result res;

    memset(thread, 0, sizeof(*thread));
    thread->fds = NULL;
    thread->nfds = 0;
    thread->res = -1;
    thread->quit = false;

    ueventCreate(&thread->done_event, false);
    ueventCreate(&thread->wake_event, true);

    res = threadCreate(&thread->t, poll_thread, thread, 0x1000, 0x2C, -2);
    if(R_FAILED(res))
    {
        printf("poll_thread_init: threadCreate failed\n");
        return res;
    }

    res = threadStart(&thread->t);
    if(R_FAILED(res))
    {
        printf("poll_thread_init: threadStart failed\n");
        threadClose(&thread->t);
    }

    return res;
}

Waiter poll_thread_waiter(poll_thread_t* thread)
{
    return waiterForUEvent(&thread->done_event);
}

int poll_thread_result(poll_thread_t* event, u64 timeout_ns)
{
    if(R_SUCCEEDED(waitSingle(waiterForUEvent(&event->done_event), timeout_ns)))
    {
        return event->res;
    }

    return -1;
}

void poll_thread_poll(poll_thread_t* thread, struct pollfd* fds, size_t nfds, int timeout)
{
    waitSingle(waiterForUEvent(&thread->done_event), UINT64_MAX);
    thread->fds = fds;
    thread->nfds = nfds;
    thread->timeout = timeout;
    ueventSignal(&thread->wake_event);
}

void poll_thread_destroy(poll_thread_t* thread)
{
    thread->quit = true;
    ueventSignal(&thread->wake_event);
    threadWaitForExit(&thread->t);
    threadClose(&thread->t);
    memset(thread, 0, sizeof(*thread));
}
