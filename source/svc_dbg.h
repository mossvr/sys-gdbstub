/*
 * dbg_svc.h
 */

#ifndef DBG_SVC_H_
#define DBG_SVC_H_


/*
 * https://switchbrew.org/wiki/SVC#DebugEventInfo
 */
typedef enum
{
    DEBUG_EVENT_ATTACH_PROCESS = 0,
    DEBUG_EVENT_ATTACH_THREAD,
    DEBUG_EVENT_EXIT_PROCESS,
    DEBUG_EVENT_EXIT_THREAD,
    DEBUG_EVENT_EXCEPTION,
} debug_event_type_t;

typedef enum
{
    DEBUG_EXIT_PAUSED_THREAD = 0,
    DEBUG_EXIT_RUNNING_THREAD,
    DEBUG_EXIT_EXITED_PROCESS,
    DEBUG_EXIT_TERMINATED_PROCESS,
} debug_exit_type_t;

typedef enum
{
    DEBUG_EXCEPTION_TRAP = 0,
    DEBUG_EXCEPTION_INSTRUCTION_ABORT,
    DEBUG_EXCEPTION_DATA_ABORT_MISC,
    DEBUG_EXCEPTION_PC_SP_ALIGNMENT_FAULT,
    DEBUG_EXCEPTION_DEBUGGER_ATTACHED,
    DEBUG_EXCEPTION_BREAKPOINT,
    DEBUG_EXCEPTION_USER_BREAK,
    DEBUG_EXCEPTION_DEBUGGER_BREAK,
    DEBUG_EXCEPTION_BAD_SVC_ID,
    DEBUG_EXCEPTION_SERROR,
} debug_exception_type_t;

typedef struct
{
    u32 type;
    u64 fault_reg;

    union
    {
        struct
        {
            u32 opcode;
        } trap;

        struct
        {
            u32 is_watchpoint;
        } breakpoint;

        struct
        {
            u32 info0;
            u64 info1;
            u64 info2;
        } user_break;

        struct
        {
            u32 svc_id;
        } bad_svc_id;
    };
} debug_exception_t;

typedef struct
{
    u32 type;
    u32 flags;
    u64 thread_id;

    union
    {
        u64 data[6];

        struct
        {
            u64 title_id;
            u64 process_id;
            char process_name[12];
            u32 mmu_flags;
            u64 user_exception_context_addr;
        } attach_process;

        struct
        {
            u64 thread_id;
            u64 tls_ptr;
            u64 entry_point;
        } attach_thread;

        struct
        {
            u32 type;
        } exit;

        debug_exception_t exception;
    };
} debug_event_t;


Result svcSetHardwareBreakPoint(u32 id, u64 flags, u64 value);


#endif /* SOURCE_DBG_SVC_H_ */
