/*
 * gdb_server.h
 */

#ifndef GDB_SERVER_H_
#define GDB_SERVER_H_

#include <stdbool.h>
#include <switch/kernel/wait.h>

typedef struct gdb_server gdb_server_t;

gdb_server_t* gdb_server_create(int port);
ssize_t gdb_server_waiters(gdb_server_t* server, Waiter* waiters, size_t max);
bool gdb_server_handle_event(gdb_server_t* server, s32 idx);
void gdb_server_destroy(gdb_server_t* server);


#endif /* GDB_SERVER_H_ */
