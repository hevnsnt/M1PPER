/* See COPYING.txt for license details. */

/*
 *
 * m1_rand.h
 *
 * Project-wide random helpers. Currently a thin wrapper over the C library
 * rand()/srand() because the firmware does not yet route TRNG into here
 * (Phase 7 work). Centralized so that when TRNG-backed randomness lands
 * the only place that has to change is m1_rand.c.
 *
 * M1 Project
 *
 */

#ifndef M1_RAND_H_
#define M1_RAND_H_

/* Seed the RNG from the current HAL tick. Safe to call multiple times. */
void m1_rand_seed(void);

/* Inclusive random integer in [min, max]. Returns min if min >= max. */
int  m1_rand_range(int min, int max);

#endif /* M1_RAND_H_ */
