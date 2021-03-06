/*
 * gdb_server.h
 */

#ifndef GDB_SERVER_H_
#define GDB_SERVER_H_

#include <stdbool.h>
#include <switch/kernel/wait.h>

#define GDB_MAX_CLIENTS 1
#define GDB_MAX_WAITERS (GDB_MAX_CLIENTS + 1)

typedef struct gdb_server gdb_server_t;

gdb_server_t* gdb_server_create(int port);
int gdb_server_waiters(gdb_server_t* server, Waiter* waiters, size_t max);
bool gdb_server_handle_event(gdb_server_t* server, int idx);
void gdb_server_destroy(gdb_server_t* server);


#endif /* GDB_SERVER_H_ */
