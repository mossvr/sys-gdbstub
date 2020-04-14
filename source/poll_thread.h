/*
 * poll_thread.h
 *
 * This provides a means for waiting on poll operations
 * using the libnx Waitable interface.
 */

#ifndef POLL_THREAD_H_
#define POLL_THREAD_H_

#include <switch.h>

typedef enum
{
    POLL_STATE_INIT,
    POLL_STATE_IDLE,
    POLL_STATE_REQUEST,
    POLL_STATE_POLLING,
    POLL_STATE_DONE,
    POLL_STATE_QUIT
} poll_state_t;

typedef struct
{
    Thread t;
    poll_state_t state;

    Mutex lock;
    CondVar cond;
    UEvent event;

    int res;
    struct pollfd* fds;
    size_t nfds;
    int timeout;
} poll_thread_t;

/**
 * Initialize and start a poll thread
 */
Result poll_thread_init(poll_thread_t* thread);

/**
 * Poll the specified file descriptors. If the previous poll operation
 * has not yet finished, this will block until it does.
 */
void poll_thread_poll(poll_thread_t* thread, struct pollfd* fds, size_t nfds, int timeout);

/**
 * Get a waiter that will be signaled when poll is finished.
 */
Waiter poll_thread_waiter(poll_thread_t* thread);

/**
 * Get the result of the poll operation. This will block until poll
 * is finished or we exceed the specified timeout, but it will not
 * cause the poll operation to time out or finish early. If the waiter
 * has already been signaled, this will not block.
 */
int poll_thread_result(poll_thread_t* thread);

/**
 * Destroy the poll thread.
 *
 * If there is a poll operation in progress when this function is
 * called, it will block until the operation is finished. Therefore,
 * you should do something that causes poll to finish early before
 * calling this function, such as closing one of the file descriptors.
 */
void poll_thread_destroy(poll_thread_t* thread);

#endif /* POLL_THREAD_H_ */
