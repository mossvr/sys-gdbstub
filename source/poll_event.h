/*
 * poll_event.h
 */

#ifndef POLL_EVENT_H_
#define POLL_EVENT_H_

#include <switch.h>

typedef struct
{
    Thread t;
    struct pollfd* fds;
    size_t nfds;
    UEvent done_event;
    UEvent wake_event;
    int res;
    bool quit;
} poll_event_t;

Result poll_event_init(poll_event_t* event);
Waiter poll_event_waiter(poll_event_t* event);
int poll_event_result(poll_event_t* event);
void poll_event_poll(poll_event_t* event, struct pollfd* fds, size_t nfds);
void poll_event_destroy(poll_event_t* event);

#endif /* POLL_EVENT_H_ */
