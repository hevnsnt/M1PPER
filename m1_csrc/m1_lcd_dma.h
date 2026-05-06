/* See COPYING.txt for license details. */

/*
 * m1_lcd_dma.h
 *
 * GPDMA configuration for the LCD SPI1 TX path.  See m1_lcd_dma.c for the
 * channel allocation map.
 */

#ifndef M1_LCD_DMA_H_
#define M1_LCD_DMA_H_

#include <stdint.h>
#include <stdbool.h>
#include "stm32h5xx_hal.h"
#include "FreeRTOS.h"
#include "semphr.h"

#ifdef __cplusplus
extern "C" {
#endif

extern DMA_HandleTypeDef          hdma_lcd_tx;
extern SemaphoreHandle_t          s_lcd_dma_done_sem;
extern volatile bool              s_lcd_dma_available;

/* Initialize GPDMA1_Channel3 for SPI1 TX and link it into the supplied SPI
 * handle.  Idempotent.  Safe to call from m1_lcd_init().  If init fails the
 * polled fallback path in m1_lcd.c keeps working. */
void m1_lcd_dma_init(SPI_HandleTypeDef *phspi);

/* True iff the DMA path is fully armed (both DMA and the binary semaphore). */
bool m1_lcd_dma_is_available(void);

/* Wait for the most recent transfer to complete.  Returns true on success,
 * false on timeout. */
bool m1_lcd_dma_wait(uint32_t timeout_ms);

/* Called from the SPI TX-complete callback to wake the waiting caller. */
void m1_lcd_dma_signal_complete_from_isr(BaseType_t *pwoken);

#ifdef __cplusplus
}
#endif

#endif /* M1_LCD_DMA_H_ */
