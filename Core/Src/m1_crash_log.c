/* m1_crash_log.c — see m1_crash_log.h */

#include "m1_crash_log.h"
#include "main.h"
#include "stm32h5xx_hal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "m1_log_debug.h"
#include <string.h>

#define M1_CRASH_LOG_TAG "Crash"

#ifndef SCB_HFSR_FORCED_Msk
#define SCB_HFSR_FORCED_Msk (1U << 30)
#endif

/* The record lives in backup SRAM via the linker .crash_log section. */
__attribute__((section(".crash_log")))
static volatile m1_crash_log_t s_crash;

/* BKPSRAM clock + write-access enable. Idempotent. */
static void crash_log_open_bkpsram(void)
{
    /* Enable backup SRAM clock on AHB4 (RCC_AHB4ENR_BKPRAMEN) */
    __HAL_RCC_BKPRAM_CLK_ENABLE();
    /* Allow writes to backup domain (set DBP). */
    HAL_PWR_EnableBkUpAccess();
    /* Enable backup-RAM regulator so contents survive across resets / VBAT. */
#ifdef PWR_BDCR_BREN
    SET_BIT(PWR->BDCR, PWR_BDCR_BREN);
#endif
}

static void copy_truncated(volatile char *dst, size_t dst_sz, const char *src)
{
    size_t i = 0;
    if (src) {
        while (i + 1 < dst_sz && src[i] != '\0') {
            dst[i] = src[i];
            i++;
        }
    }
    if (dst_sz > 0) {
        dst[i] = '\0';
    }
}

static const char *path_tail(const char *path)
{
    if (!path) return "";
    const char *t = path;
    for (const char *p = path; *p; ++p) {
        if (*p == '/' || *p == '\\') t = p + 1;
    }
    return t;
}

/* Best-effort current task name. Returns "" if FreeRTOS not running yet. */
static const char *crash_get_task_name(void)
{
    if (xTaskGetSchedulerState() == taskSCHEDULER_NOT_STARTED) {
        return "<pre-rtos>";
    }
    TaskHandle_t h = xTaskGetCurrentTaskHandle();
    if (h == NULL) return "<no-task>";
    return pcTaskGetName(h);
}

/* Common fault recording. Captures regs, writes to BKPSRAM, resets. */
void m1_crash_record_fault(m1_crash_kind_t kind,
                           const m1_crash_frame_t *frame,
                           uint32_t exc_return)
{
    crash_log_open_bkpsram();
    s_crash.magic       = M1_CRASH_MAGIC;
    s_crash.kind        = (uint32_t)kind;
    s_crash.cfsr        = SCB->CFSR;
    s_crash.hfsr        = SCB->HFSR;
    s_crash.mmfar       = SCB->MMFAR;
    s_crash.bfar        = SCB->BFAR;
    s_crash.exc_return  = exc_return;
    if (frame) {
        s_crash.frame.r0  = frame->r0;
        s_crash.frame.r1  = frame->r1;
        s_crash.frame.r2  = frame->r2;
        s_crash.frame.r3  = frame->r3;
        s_crash.frame.r12 = frame->r12;
        s_crash.frame.lr  = frame->lr;
        s_crash.frame.pc  = frame->pc;
        s_crash.frame.psr = frame->psr;
    } else {
        memset((void *)&s_crash.frame, 0, sizeof(s_crash.frame));
    }
    copy_truncated(s_crash.task_name, sizeof(s_crash.task_name),
                   crash_get_task_name());
    s_crash.assert_line = 0;
    s_crash.assert_file[0] = '\0';

    __DSB();
    NVIC_SystemReset();
    while (1) { } /* unreachable */
}

void m1_crash_record_assert(const char *file, uint32_t line)
{
    crash_log_open_bkpsram();
    s_crash.magic       = M1_CRASH_MAGIC;
    s_crash.kind        = (uint32_t)M1_CRASH_ASSERT;
    s_crash.cfsr        = 0;
    s_crash.hfsr        = 0;
    s_crash.mmfar       = 0;
    s_crash.bfar        = 0;
    s_crash.exc_return  = 0;
    memset((void *)&s_crash.frame, 0, sizeof(s_crash.frame));
    copy_truncated(s_crash.task_name, sizeof(s_crash.task_name),
                   crash_get_task_name());
    s_crash.assert_line = line;
    copy_truncated(s_crash.assert_file, sizeof(s_crash.assert_file),
                   path_tail(file));

    __DSB();
    NVIC_SystemReset();
    while (1) { }
}

void m1_crash_record_simple(m1_crash_kind_t kind, const char *task_name)
{
    crash_log_open_bkpsram();
    s_crash.magic       = M1_CRASH_MAGIC;
    s_crash.kind        = (uint32_t)kind;
    s_crash.cfsr        = SCB->CFSR;
    s_crash.hfsr        = SCB->HFSR;
    s_crash.mmfar       = SCB->MMFAR;
    s_crash.bfar        = SCB->BFAR;
    s_crash.exc_return  = 0;
    memset((void *)&s_crash.frame, 0, sizeof(s_crash.frame));
    copy_truncated(s_crash.task_name, sizeof(s_crash.task_name),
                   task_name ? task_name : crash_get_task_name());
    s_crash.assert_line = 0;
    s_crash.assert_file[0] = '\0';

    __DSB();
    NVIC_SystemReset();
    while (1) { }
}

static const char *crash_kind_str(uint32_t k)
{
    switch (k) {
    case M1_CRASH_HARDFAULT:     return "HardFault";
    case M1_CRASH_MEMMANAGE:     return "MemManage";
    case M1_CRASH_BUSFAULT:      return "BusFault";
    case M1_CRASH_USAGEFAULT:    return "UsageFault";
    case M1_CRASH_NMI:           return "NMI";
    case M1_CRASH_ASSERT:        return "Assert";
    case M1_CRASH_STACK_OVF:     return "StackOverflow";
    case M1_CRASH_MALLOC_FAIL:   return "MallocFail";
    case M1_CRASH_ERROR_HANDLER: return "ErrorHandler";
    default:                     return "Unknown";
    }
}

void m1_crash_log_check_and_log(void)
{
    crash_log_open_bkpsram();

    /* Boot counter is always incremented (records or no records). It uses
     * the same backup region so survives reset; useful as a heartbeat. */
    uint32_t prev_boot = s_crash.boot_count;

    if (s_crash.magic == M1_CRASH_MAGIC && s_crash.kind != M1_CRASH_NONE) {
        const char *kind = crash_kind_str(s_crash.kind);
        if (s_crash.kind == M1_CRASH_ASSERT) {
            M1_LOG_E(M1_CRASH_LOG_TAG, "%s task=%s file=%s line=%lu",
                     kind,
                     (const char *)s_crash.task_name,
                     (const char *)s_crash.assert_file,
                     (unsigned long)s_crash.assert_line);
        } else {
            M1_LOG_E(M1_CRASH_LOG_TAG,
                     "%s task=%s pc=0x%08lX lr=0x%08lX "
                     "cfsr=0x%08lX hfsr=0x%08lX mmfar=0x%08lX bfar=0x%08lX",
                     kind,
                     (const char *)s_crash.task_name,
                     (unsigned long)s_crash.frame.pc,
                     (unsigned long)s_crash.frame.lr,
                     (unsigned long)s_crash.cfsr,
                     (unsigned long)s_crash.hfsr,
                     (unsigned long)s_crash.mmfar,
                     (unsigned long)s_crash.bfar);
        }
    }

    /* Clear after logging, increment boot counter. */
    s_crash.magic = 0;
    s_crash.kind  = M1_CRASH_NONE;
    s_crash.boot_count = prev_boot + 1;
    __DSB();
}
