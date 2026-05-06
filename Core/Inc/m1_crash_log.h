/* m1_crash_log.h — Persistent crash telemetry across reset.
 *
 * On hard fault, mem-manage fault, bus fault, usage fault, assert failure,
 * stack overflow, or malloc failure: capture state into BKPSRAM, then reset.
 * On next boot main() calls m1_crash_log_check_and_log() which surfaces the
 * record via M1_LOG and clears it.
 *
 * BKPSRAM region is declared in STM32H573VITX_FLASH.ld as 'BKPSRAM' and the
 * .crash_log section is NOLOAD so contents survive software reset.
 */
#ifndef M1_CRASH_LOG_H_
#define M1_CRASH_LOG_H_

#include <stdint.h>
#include <stdbool.h>

#define M1_CRASH_MAGIC          0x4D314346U  /* "M1CF" */
#define M1_CRASH_TASK_NAME_MAX  16
#define M1_CRASH_FILE_MAX       32

typedef enum {
    M1_CRASH_NONE          = 0,
    M1_CRASH_HARDFAULT     = 1,
    M1_CRASH_MEMMANAGE     = 2,
    M1_CRASH_BUSFAULT      = 3,
    M1_CRASH_USAGEFAULT    = 4,
    M1_CRASH_NMI           = 5,
    M1_CRASH_ASSERT        = 6,
    M1_CRASH_STACK_OVF     = 7,
    M1_CRASH_MALLOC_FAIL   = 8,
    M1_CRASH_ERROR_HANDLER = 9,
} m1_crash_kind_t;

/* Stacked exception frame (basic, no FP). Order matches Cortex-M push. */
typedef struct {
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r12;
    uint32_t lr;
    uint32_t pc;
    uint32_t psr;
} m1_crash_frame_t;

typedef struct {
    uint32_t magic;        /* M1_CRASH_MAGIC when valid */
    uint32_t kind;         /* m1_crash_kind_t */
    uint32_t boot_count;   /* increments every boot — sanity check on persistence */
    /* Cortex-M fault status registers (only meaningful for fault kinds) */
    uint32_t cfsr;
    uint32_t hfsr;
    uint32_t mmfar;
    uint32_t bfar;
    uint32_t exc_return;   /* LR at handler entry */
    /* Stacked frame at moment of fault */
    m1_crash_frame_t frame;
    /* Context */
    char     task_name[M1_CRASH_TASK_NAME_MAX];
    /* Assert / Error_Handler context (line number; file is path tail) */
    uint32_t assert_line;
    char     assert_file[M1_CRASH_FILE_MAX];
} m1_crash_log_t;

/* Called from main() once before scheduler start. Reads BKPSRAM, logs any
 * pending crash record, clears the record, increments boot_count. Safe to
 * call when no crash is recorded. */
void m1_crash_log_check_and_log(void);

/* Generic write helpers used by fault handlers, configASSERT, etc.
 * These do NOT return — they reset the device after recording. */
void m1_crash_record_fault(m1_crash_kind_t kind,
                           const m1_crash_frame_t *frame,
                           uint32_t exc_return) __attribute__((noreturn));
void m1_crash_record_assert(const char *file, uint32_t line) __attribute__((noreturn));
void m1_crash_record_simple(m1_crash_kind_t kind, const char *task_name) __attribute__((noreturn));

#endif /* M1_CRASH_LOG_H_ */
