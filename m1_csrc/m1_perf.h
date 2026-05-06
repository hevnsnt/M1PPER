/* See COPYING.txt for license details. */

/*
 * m1_perf.h
 *
 * Cheap profiling helpers backed by the Cortex-M33 DWT cycle counter.
 *
 * The counter is enabled in main() before any task runs (Core/Src/main.c
 * USER CODE BEGIN Init) so callers can read it without a setup dance.
 * Resolution is 1 core cycle (13.3 ns at 75 MHz, 4 ns at 250 MHz).  The
 * 32-bit counter wraps every ~57 sec at 75 MHz / ~17 sec at 250 MHz, so
 * compare deltas with subtraction (uint32 underflow handles the wrap).
 *
 * Typical use:
 *
 *     uint32_t t0 = m1_perf_cycles();
 *     do_thing();
 *     uint32_t dt = m1_perf_cycles() - t0;
 *     M1_LOG_I("PERF", "do_thing: %lu cycles\r\n", (unsigned long)dt);
 *
 * Audit 07 hardware-features-unused: "DWT cycle counter for cheap
 * profiling".  Standardized via this header.
 */

#ifndef M1_PERF_H_
#define M1_PERF_H_

#include <stdint.h>
#include "stm32h5xx_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Read the DWT cycle counter.  One CPU cycle. */
static inline uint32_t m1_perf_cycles(void)
{
    return DWT->CYCCNT;
}

/* Convert a cycle delta to microseconds.  Caller passes the current
 * SystemCoreClock in Hz (or hardcoded constant when known). */
static inline uint32_t m1_perf_cycles_to_us(uint32_t cycles, uint32_t hclk_hz)
{
    if (hclk_hz < 1000000U)
        return cycles; /* fallback: cycles ~= us under 1 MHz core */
    return (uint32_t)((uint64_t)cycles * 1000000ULL / hclk_hz);
}

#ifdef __cplusplus
}
#endif

#endif /* M1_PERF_H_ */
