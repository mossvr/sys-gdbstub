/*
 * gdb_stub.h
 */

#ifndef GDB_STUB_H_
#define GDB_STUB_H_

#include <stdint.h>
#include <stddef.h>

#include <switch.h>

typedef struct gdb_stub gdb_stub_t;

typedef void (*gdb_stub_output_t)(gdb_stub_t* stub, char* buffer, size_t length, void* arg);

gdb_stub_t* gdb_stub_create(gdb_stub_output_t output, void* arg);
void gdb_stub_input(gdb_stub_t* stub, char* buffer, size_t length);
void gdb_stub_destroy(gdb_stub_t* stub);
Result gdb_stub_get_waiter(gdb_stub_t* stub, Waiter* waiter);
void gdb_stub_handle_events(gdb_stub_t* stub);

#endif /* GDB_STUB_H_ */
