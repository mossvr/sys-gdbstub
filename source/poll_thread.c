
#include <string.h>
#include <poll.h>
#include <stdio.h>

#include "poll_thread.h"

#if 0
#define logf(fmt, ...) printf("poll_thread: " fmt, ##__VA_ARGS__)
#else
#define logf(fmt, ...)
#endif


static void poll_thread(void* arg)
{
    poll_thread_t* thread = (poll_thread_t*)arg;

    mutexLock(&thread->lock);
    thread->state = POLL_STATE_IDLE;
    condvarWakeAll(&thread->cond);

    while (true)
    {
        while (thread->state != POLL_STATE_REQUEST &&
            thread->state != POLL_STATE_QUIT)
        {
            condvarWait(&thread->cond, &thread->lock);
        }

        if (thread->state == POLL_STATE_QUIT)
        {
            break;
        }

        thread->state = POLL_STATE_POLLING;
        mutexUnlock(&thread->lock);

        logf("polling (nfds=%lu, timeout=%d)\n", thread->nfds, thread->timeout);
        thread->res = poll(thread->fds, thread->nfds, thread->timeout);
        logf("done polling (res=%d)\n", thread->res);

        mutexLock(&thread->lock);
        thread->state = POLL_STATE_DONE;
        condvarWakeAll(&thread->cond);
        ueventSignal(&thread->event);
    }

    mutexUnlock(&thread->lock);

    logf("exiting...\n");
}

Result poll_thread_init(poll_thread_t* thread)
{
    logf("%s\n", __FUNCTION__);
    
    Result res;

    memset(thread, 0, sizeof(*thread));
    thread->state = POLL_STATE_INIT;
    thread->fds = NULL;
    thread->nfds = 0;
    thread->res = -2;

    mutexInit(&thread->lock);
    condvarInit(&thread->cond);
    ueventCreate(&thread->event, true);

    res = threadCreate(&thread->t, poll_thread, thread, NULL, 0x1000, 0x2C, -2);
    if (R_FAILED(res))
    {
        logf("threadCreate failed\n");
        return res;
    }

    res = threadStart(&thread->t);
    if (R_FAILED(res))
    {
        logf("threadStart failed\n");
        threadClose(&thread->t);
        return res;
    }

    mutexLock(&thread->lock);
    while (thread->state == POLL_STATE_INIT)
    {
        condvarWait(&thread->cond, &thread->lock);
    }
    mutexUnlock(&thread->lock);

    return res;
}

Waiter poll_thread_waiter(poll_thread_t* thread)
{
    return waiterForUEvent(&thread->event);
}

int poll_thread_result(poll_thread_t* thread)
{
    logf("%s\n", __FUNCTION__);
    int res;

    mutexLock(&thread->lock);
    if (thread->state != POLL_STATE_DONE)
    {
        mutexUnlock(&thread->lock);
        logf("not done\n");
        return -1;
    }

    res = thread->res;
    thread->state = POLL_STATE_IDLE;
    condvarWakeAll(&thread->cond);
    mutexUnlock(&thread->lock);
    return res;
}

void poll_thread_poll(poll_thread_t* thread, struct pollfd* fds, size_t nfds, int timeout)
{
    logf("%s (nfds=%lu, timeout=%d)\n", __FUNCTION__, nfds, timeout);

    mutexLock(&thread->lock);
    if (thread->state != POLL_STATE_IDLE)
    {
        logf("not idle\n");
        mutexUnlock(&thread->lock);
        return;
    }

    thread->state = POLL_STATE_REQUEST;
    thread->fds = fds;
    thread->nfds = nfds;
    thread->timeout = timeout;
    thread->res = -2;
    ueventClear(&thread->event);
    condvarWakeAll(&thread->cond);
    mutexUnlock(&thread->lock);
}

void poll_thread_destroy(poll_thread_t* thread)
{
    logf("%s\n", __FUNCTION__);
    mutexLock(&thread->lock);

    // wait for the thread to finish
    while (thread->state != POLL_STATE_IDLE &&
        thread->state != POLL_STATE_DONE)
    {
        condvarWait(&thread->cond, &thread->lock);
    }

    // tell the thread to quit
    thread->state = POLL_STATE_QUIT;
    condvarWakeAll(&thread->cond);
    mutexUnlock(&thread->lock);

    // wait for the thread to exit
    threadWaitForExit(&thread->t);
    threadClose(&thread->t);
    memset(thread, 0, sizeof(*thread));
}
