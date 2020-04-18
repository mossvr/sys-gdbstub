
#ifndef GDB_MAIN_H_
#define GDB_MAIN_H_

#include <stdint.h>

int gdb_main_init(void);
int gdb_main_run(uint64_t timeout);
void gdb_main_exit(void);

#endif /* GDB_MAIN_H_ */