/* See COPYING.txt for license details. */

/*
 *
 * m1_rand.c
 *
 * See m1_rand.h.
 *
 * M1 Project
 *
 */

#include <stdlib.h>
#include "stm32h5xx_hal.h"
#include "m1_rand.h"

void m1_rand_seed(void)
{
    srand(HAL_GetTick());
}

int m1_rand_range(int min, int max)
{
    if (min >= max)
    {
        return min;
    }
    return min + (rand() % (max - min + 1));
}
