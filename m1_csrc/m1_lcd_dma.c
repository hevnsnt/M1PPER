/* See COPYING.txt for license details. */

/*
 * m1_lcd_dma.c
 *
 * GPDMA configuration for the LCD SPI1 TX path.  Lives in its own TU so the
 * change does not require an edit to Core/Src/main.c (Phase 1 owns the
 * SystemClock_Config nearby and we don't want to risk a merge collision
 * across phases).  Called once from m1_lcd_init() at boot.
 *
 * Channel allocation (audit 07 + audit 01):
 *
 *   Channel 0  Sub-GHz Si4463 TX             m1_sub_ghz.c:3944
 *   Channel 1  USART1 (debug log)  TX        m1_log_debug.c:257
 *   Channel 2  USART1 (debug log)  RX        m1_log_debug.c:223
 *   Channel 3  SPI1 TX (LCD)                 <-- this file
 *   Channel 4  ESP32 UART4 RX                m1_esp32_hal.c
 *   Channel 5  ESP32 UART4 TX                m1_esp32_hal.c:318
 *   Channel 6  free
 *   Channel 7  free
 *
 * SPI1 native HW request id: GPDMA1_REQUEST_SPI1_TX (= 7).
 *
 * The display tile buffer pushed by u8g2_SendBuffer() is up to 1024 bytes
 * (128 * 64 / 8) for the ST7567 panel.  GPDMA1 can do that in a single
 * block transfer.  The completion callback gives a binary semaphore that
 * the caller waits on before allowing the framebuffer to be reused.
 *
 * Failure mode: if HAL_DMA_Init returns non-OK we leave hspi->hdmatx as
 * NULL and the existing polled HAL_SPI_Transmit path in m1_lcd.c is used
 * instead.  No regression, just no DMA acceleration.
 */

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_freertos.h"
#include "semphr.h"
#include "m1_lcd_dma.h"
#include "m1_log_debug.h"

/*************************** D E F I N E S ************************************/

#define M1_LOGDB_TAG       "LCDDMA"

/***************************** V A R I A B L E S ******************************/

DMA_HandleTypeDef          hdma_lcd_tx;
SemaphoreHandle_t          s_lcd_dma_done_sem  = NULL;
volatile bool              s_lcd_dma_available = false;

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

void m1_lcd_dma_init(SPI_HandleTypeDef *phspi)
{
    if (phspi == NULL)
        return;

    /* Binary semaphore for completion handoff between IRQ and caller task. */
    s_lcd_dma_done_sem = xSemaphoreCreateBinary();
    if (s_lcd_dma_done_sem == NULL)
    {
        M1_LOG_W(M1_LOGDB_TAG, "sem alloc failed; falling back to polled SPI\r\n");
        return;
    }

    /* Make sure GPDMA1 clock is on (already turned on for log + sub-GHz, but
     * defensive). */
    __HAL_RCC_GPDMA1_CLK_ENABLE();

    hdma_lcd_tx.Instance                 = GPDMA1_Channel3;
    hdma_lcd_tx.Init.Request             = GPDMA1_REQUEST_SPI1_TX;
    hdma_lcd_tx.Init.BlkHWRequest        = DMA_BREQ_SINGLE_BURST;
    hdma_lcd_tx.Init.Direction           = DMA_MEMORY_TO_PERIPH;
    hdma_lcd_tx.Init.SrcInc              = DMA_SINC_INCREMENTED;
    hdma_lcd_tx.Init.DestInc             = DMA_DINC_FIXED;
    hdma_lcd_tx.Init.SrcDataWidth        = DMA_SRC_DATAWIDTH_BYTE;
    hdma_lcd_tx.Init.DestDataWidth       = DMA_DEST_DATAWIDTH_BYTE;
    hdma_lcd_tx.Init.Priority            = DMA_LOW_PRIORITY_HIGH_WEIGHT;
    hdma_lcd_tx.Init.SrcBurstLength      = 1;
    hdma_lcd_tx.Init.DestBurstLength     = 1;
    hdma_lcd_tx.Init.TransferAllocatedPort
        = DMA_SRC_ALLOCATED_PORT0 | DMA_DEST_ALLOCATED_PORT1;
    hdma_lcd_tx.Init.TransferEventMode   = DMA_TCEM_BLOCK_TRANSFER;
    hdma_lcd_tx.Init.Mode                = DMA_NORMAL;

    if (HAL_DMA_Init(&hdma_lcd_tx) != HAL_OK)
    {
        M1_LOG_E(M1_LOGDB_TAG, "HAL_DMA_Init(SPI1_TX) failed\r\n");
        vSemaphoreDelete(s_lcd_dma_done_sem);
        s_lcd_dma_done_sem = NULL;
        return;
    }

    if (HAL_DMA_ConfigChannelAttributes(&hdma_lcd_tx, DMA_CHANNEL_NPRIV) != HAL_OK)
    {
        M1_LOG_E(M1_LOGDB_TAG, "HAL_DMA_ConfigChannelAttributes failed\r\n");
        return;
    }

    /* Wire the DMA into the SPI handle so HAL_SPI_Transmit_DMA can find it. */
    __HAL_LINKDMA(phspi, hdmatx, hdma_lcd_tx);

    /* IRQ priority must be lower-or-equal-numbered than
     * configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY so FromISR APIs are legal
     * (we give a semaphore in HAL_SPI_TxCpltCallback). */
    HAL_NVIC_SetPriority(GPDMA1_Channel3_IRQn,
                         configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY, 0);
    HAL_NVIC_EnableIRQ(GPDMA1_Channel3_IRQn);

    s_lcd_dma_available = true;
    M1_LOG_I(M1_LOGDB_TAG, "SPI1_TX DMA armed on GPDMA1_Channel3\r\n");
}

bool m1_lcd_dma_is_available(void)
{
    return s_lcd_dma_available;
}

bool m1_lcd_dma_wait(uint32_t timeout_ms)
{
    if (s_lcd_dma_done_sem == NULL)
        return true;
    if (xSemaphoreTake(s_lcd_dma_done_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE)
        return false;
    return true;
}

void m1_lcd_dma_signal_complete_from_isr(BaseType_t *pwoken)
{
    if (s_lcd_dma_done_sem != NULL)
        xSemaphoreGiveFromISR(s_lcd_dma_done_sem, pwoken);
}

/*============================================================================*/
/* IRQ handler.  HAL chains DMA -> HAL_SPI_TxCpltCallback (defined in m1_lcd.c)
 * which then signals the semaphore.
 */
/*============================================================================*/
void GPDMA1_Channel3_IRQHandler(void)
{
    HAL_DMA_IRQHandler(&hdma_lcd_tx);
}
