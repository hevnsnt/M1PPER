/* See COPYING.txt for license details. */

/*
*
*  m1_lcd.c
*
*  M1 lcd display functions
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "app_freertos.h"
#include "semphr.h"
#include "main.h"
//#include "u8g2.h"
//#include "mui.h"
#include "m1_rf_spi.h"
//#include "u8x8.h"
//#include "U8g2lib.h"
#include "m1_compile_cfg.h"
#include "m1_lcd.h"
#include "m1_lcd_dma.h"
#ifdef M1_APP_RPC_ENABLE
#include "m1_rpc.h"
#endif

/* Access to the on-chip HW CRC unit, configured in MX_CRC_Init() (main.c).
 * Used for framebuffer dirty-check skip: when nothing has changed since the
 * last m1_u8g2_nextpage() the SPI push (and the ~440us blocking transfer at
 * the current 18.75 MHz) is skipped entirely.  Audit 07 finding "framebuffer
 * dirty check via HW CRC32 of the tile buffer". */
extern CRC_HandleTypeDef hcrc;

/* DMA TX timeout for a full ST7567 page (8 page slices of 128 bytes plus a
 * handful of cmd byte handoffs).  At 18.75 MHz wire rate the full frame is
 * ~440us; 50 ms is 100x headroom and matches other peripheral timeouts. */
#define M1_LCD_DMA_TIMEOUT_MS      50U

/*************************** D E F I N E S ************************************/

//************************** C O N S T A N T **********************************/

//************************** S T R U C T U R E S *******************************

/***************************** V A R I A B L E S ******************************/

u8g2_t m1_u8g2;
SPI_HandleTypeDef *plcd_hspi;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

uint8_t u8x8_byte_stm32_4wire_hw_spi(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr);
uint8_t u8x8_stm32_gpio_and_delay(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr);
void m1_lcd_init(SPI_HandleTypeDef *phspi);

void m1_u8g2_firstpage(void);
uint8_t m1_u8g2_nextpage(void);
void m1_lcd_cleardisplay(void);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

/*============================================================================*/
/*
 * This functions is used to interface to the communication port of the display controller, i.e. SPI, I2C, etc.
 * This interface may either be implemented as a bit-banged software interface or using the MCU specific hardware
 * This function takes a "msg" which is one of many #defines found in u8x8.h"
 */
/*============================================================================*/
uint8_t u8x8_byte_stm32_4wire_hw_spi(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr)
{
	HAL_StatusTypeDef status;

	switch (msg)
	{
		// Send one or more bytes, located at arg_ptr, arg_int contains the number of bytes.
		case U8X8_MSG_BYTE_SEND:
			/* DMA path: only worth the kick-off cost above ~16 bytes.  Below
			 * that (single-cmd handoffs during init/refresh) the polled path
			 * is faster end-to-end and lets us skip the semaphore wait.
			 * The semaphore-take in m1_lcd_dma_wait() yields to other tasks
			 * while the GPDMA + SPI engines drive the bus, so the menu task
			 * gives back ~440us to FreeRTOS on every full-page push. */
			if (m1_lcd_dma_is_available() && arg_int > 16U)
			{
				status = HAL_SPI_Transmit_DMA(plcd_hspi, (uint8_t *)arg_ptr, arg_int);
				if (status != HAL_OK)
				{
					return 0;
				}
				if (!m1_lcd_dma_wait(M1_LCD_DMA_TIMEOUT_MS))
				{
					HAL_SPI_Abort(plcd_hspi);
					return 0;
				}
			}
			else
			{
				status = HAL_SPI_Transmit(plcd_hspi, (uint8_t *)arg_ptr, arg_int, SPI_WRITE_TIMEOUT);
				if (status != HAL_OK)
				{
					return 0; // Error
				}
			}

			break;

		// Send once during the init phase of the display
		case U8X8_MSG_BYTE_INIT:
			break;

		// Set the level of the data/command pin. arg_int contains the expected output level.
		// Use u8x8_gpio_SetDC(u8x8, arg_int) to send a message to the GPIO procedure.
		case U8X8_MSG_BYTE_SET_DC:
			HAL_GPIO_WritePin(Display_DI_GPIO_Port, Display_DI_Pin, arg_int);
			break;

		// Set the chip select line here. u8x8->display_info->chip_enable_level contains the expected level.
		// Use u8x8_gpio_SetCS(u8x8, u8x8->display_info->chip_enable_level) to call the GPIO procedure.
		case U8X8_MSG_BYTE_START_TRANSFER:
			HAL_GPIO_WritePin(Display_CS_GPIO_Port, Display_CS_Pin, GPIO_PIN_RESET);
			break;

		// Unselect the device. Use the CS level from here: u8x8->display_info->chip_disable_level.
		case U8X8_MSG_BYTE_END_TRANSFER:
			HAL_GPIO_WritePin(Display_CS_GPIO_Port, Display_CS_Pin, GPIO_PIN_SET);
			break;

		default:
			return 0;
	} // switch (msg)

	return 1;
} // uint8_t u8x8_byte_stm32_4wire_hw_spi(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr)



/*============================================================================*/
/*
 * This function is used to read, set and reset GPIOs.
 * This function takes a "msg" which is one of many #defines found in u8x8.h.
 * The return value should be 1 (true) for successful handling of the message."
 */
/*============================================================================*/
uint8_t u8x8_stm32_gpio_and_delay(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr)
{
	switch (msg)
	{
		case U8X8_MSG_GPIO_MENU_SELECT:
			//u8x8->gpio_result = HAL_GPIO_ReadPin(BUTTON_OK_GPIO_Port, BUTTON_OK_GPIO_Pin);
			u8x8->gpio_result = (buttons_ctl[BUTTON_OK_KP_ID].event==BUTTON_EVENT_CLICK) ? 0 : 1; // u8g2 translates 0 as button pressed
			break;

		case U8X8_MSG_GPIO_MENU_NEXT:
			u8x8->gpio_result = (buttons_ctl[m1_southpaw_mode ? BUTTON_LEFT_KP_ID : BUTTON_RIGHT_KP_ID].event==BUTTON_EVENT_CLICK) ? 0 : 1;
			break;

		case U8X8_MSG_GPIO_MENU_PREV:
			u8x8->gpio_result = (buttons_ctl[m1_southpaw_mode ? BUTTON_RIGHT_KP_ID : BUTTON_LEFT_KP_ID].event==BUTTON_EVENT_CLICK) ? 0 : 1;
			break;

		case U8X8_MSG_GPIO_MENU_HOME:
			u8x8->gpio_result = (buttons_ctl[BUTTON_BACK_KP_ID].event==BUTTON_EVENT_CLICK) ? 0 : 1;
			break;

		case U8X8_MSG_GPIO_MENU_UP:
			u8x8->gpio_result = (buttons_ctl[m1_southpaw_mode ? BUTTON_DOWN_KP_ID : BUTTON_UP_KP_ID].event==BUTTON_EVENT_CLICK) ? 0 : 1;
			break;

		case U8X8_MSG_GPIO_MENU_DOWN:
			u8x8->gpio_result = (buttons_ctl[m1_southpaw_mode ? BUTTON_UP_KP_ID : BUTTON_DOWN_KP_ID].event==BUTTON_EVENT_CLICK) ? 0 : 1;
			break;

		case U8X8_MSG_GPIO_AND_DELAY_INIT:
			HAL_Delay(1);
			break;

		case U8X8_MSG_DELAY_MILLI:
			HAL_Delay(arg_int);
			break;

		case U8X8_MSG_GPIO_DC:
			HAL_GPIO_WritePin(Display_DI_GPIO_Port, Display_DI_Pin, arg_int);
			break;

		case U8X8_MSG_GPIO_RESET:
			HAL_GPIO_WritePin(Display_RST_GPIO_Port, Display_RST_Pin, arg_int);
			break;

		default:
			u8x8_SetGPIOResult(u8x8, 1);			// default return value
			break;
	} // switch (msg)

	return 1;
} // uint8_t u8x8_stm32_gpio_and_delay(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr)



/*============================================================================*/
/*
 * This function initializes the LCD display
 */
/*============================================================================*/
void m1_lcd_init(SPI_HandleTypeDef *phspi)
{
	assert(phspi!=NULL);
	plcd_hspi = phspi;

	/* Wire up SPI1 TX DMA before the first transfer so panel init itself
	 * benefits.  Failure path leaves DMA disabled and the polled path
	 * continues to work. */
	m1_lcd_dma_init(phspi);

    HAL_Delay(2); // Wait for stable power after power on, > 1ms
    u8g2_Setup_st7567_enh_dg128064i_f(&m1_u8g2, U8G2_R2, u8x8_byte_stm32_4wire_hw_spi, u8x8_stm32_gpio_and_delay);
	u8g2_InitDisplay(&m1_u8g2);

	// Custom init for the LCD
	// This helps to minimize the flickering effect on the display
	// minimize the effect of visible grid patterns
	u8x8_cad_StartTransfer(&m1_u8g2.u8x8);
	// Set Regulation Ratio down to 2, default after init is 3
	u8x8_cad_SendCmd(&m1_u8g2.u8x8, 0x22);
	// Set contrast
    u8x8_cad_SendCmd(&m1_u8g2.u8x8, 0x081);
    u8x8_cad_SendArg(&m1_u8g2.u8x8, 235 >> 2);
	u8x8_cad_EndTransfer(&m1_u8g2.u8x8);

	//Set power save mode ON to clear any unwanted objects displayed on the LCD unexpectedly after POR
	u8g2_SetPowerSave(&m1_u8g2, true);

	/* First post-boot frame must always push — the panel may have any prior
	 * state and our local CRC cache is uninitialized before the first call.
	 * The sentinel value already in s_lcd_last_crc handles this; explicit
	 * call here is documentation more than action. */
	m1_lcd_force_redraw();

} // void m1_lcd_init(SPI_HandleTypeDef *phspi)


/*============================================================================*/
/* HAL SPI TxCpltCallback override.
 *
 * The HAL ships a weak default that does nothing; we install a strong one
 * here that signals the LCD DMA semaphore for SPI1 transfers and is a no-op
 * for any other SPI instance (SPI2 = NFC + Si4463 is still polled).
 */
/*============================================================================*/
void HAL_SPI_TxCpltCallback(SPI_HandleTypeDef *hspi)
{
    if (hspi == plcd_hspi)
    {
        BaseType_t hpw = pdFALSE;
        m1_lcd_dma_signal_complete_from_isr(&hpw);
        portYIELD_FROM_ISR(hpw);
    }
}


/*============================================================================*/
/**
  * @brief  Set southpaw (left-handed) display rotation
  * @param  enable: 1=southpaw (R0), 0=normal (R2)
  */
/*============================================================================*/
void m1_lcd_set_southpaw(uint8_t enable)
{
    const u8g2_cb_t *rot = enable ? U8G2_R0 : U8G2_R2;
    u8g2_SetDisplayRotation(&m1_u8g2, rot);
}


/*============================================================================*/
/*
 * This function is the equivalent of the function void u8g2_FirstPage(u8g2_t *u8g2)
 */
/*============================================================================*/
void m1_u8g2_firstpage(void)
{
    u8g2_ClearBuffer(&m1_u8g2);
    u8g2_SetBufferCurrTileRow(&m1_u8g2, 0);
} // void m1_u8g2_firstpage(void)


/*============================================================================*/
/*
 * Framebuffer dirty-check via HW CRC32.
 *
 * The display tile buffer is 128 * (64/8) = 1024 bytes.  Pushing it over SPI
 * at 18.75 MHz takes ~440 us blocking on the menu task's stack — that's
 * tens of frames per second wasted when the UI is idle (clock tick, idle
 * pulse animations, status panels that haven't changed).  We hash the tile
 * buffer through the on-chip HW CRC unit (~1 cycle/word -> 64 cycles for
 * 1 KB, 200x cheaper than the SPI push) and skip the push entirely if the
 * CRC matches the previously-pushed frame.
 *
 * Cache management:
 *   - s_lcd_last_crc starts at "force-push" sentinel so the first frame
 *     after boot or any caller of m1_lcd_force_redraw always pushes.
 *   - m1_lcd_force_redraw() invalidates the cache for callers that flip
 *     the display state outside the u8g2 buffer (power save, contrast,
 *     hardware rotation, etc.).
 */
/*============================================================================*/
#define M1_LCD_FORCE_REDRAW_SENTINEL    0xDEADBEEFUL
static uint32_t s_lcd_last_crc = M1_LCD_FORCE_REDRAW_SENTINEL;

void m1_lcd_force_redraw(void)
{
    s_lcd_last_crc = M1_LCD_FORCE_REDRAW_SENTINEL;
}

uint8_t m1_u8g2_nextpage(void)
{
    uint8_t  *bp     = u8g2_GetBufferPtr(&m1_u8g2);
    uint16_t  bytes  = (uint16_t)(u8g2_GetBufferTileWidth(&m1_u8g2) * 8U *
                                  u8g2_GetBufferTileHeight(&m1_u8g2));
    uint32_t  words  = (uint32_t)(bytes / 4U);
    uint32_t  crc    = M1_LCD_FORCE_REDRAW_SENTINEL;

    if (bp != NULL && words > 0U)
    {
        /* HAL_CRC_Calculate processes 32-bit words; the framebuffer is 1024
         * bytes -> 256 words at 128x64.  Buffer is 4-byte aligned because
         * u8g2_t embeds it after a uint32_t-aligned struct. */
        crc = HAL_CRC_Calculate(&hcrc, (uint32_t *)(uintptr_t)bp, words);
    }

    if (crc != s_lcd_last_crc)
    {
        u8g2_SendBuffer(&m1_u8g2);
        u8x8_RefreshDisplay( u8g2_GetU8x8(&m1_u8g2) );
        s_lcd_last_crc = crc;

#ifdef M1_APP_RPC_ENABLE
        /* Notify the RPC task that a new frame is ready for streaming.  Only
         * publish on actual frame change so qMonstatek isn't spammed with
         * identical frames. */
        if (m1_rpc_screen_streaming_active())
        {
            m1_rpc_notify_screen_update();
        }
#endif
    }
    /* If the frame is unchanged we still return success — callers expect a
     * page-loop progression even when the SPI push is elided. */

    return 0;
} // uint8_t m1_u8g2_nextpage(void)



/*============================================================================*/
/*
 * This function clears the display with inverted color effect
 * It is used to replace the default function u8g2_ClearDisplay()
 */
/*============================================================================*/
void m1_lcd_cleardisplay(void)
{
	u8g2_ClearBuffer(&m1_u8g2);
	u8g2_SetBufferCurrTileRow(&m1_u8g2, 0);

	m1_u8g2_nextpage();
	u8g2_SetBufferCurrTileRow(&m1_u8g2, 0);

	u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT); // set the color to Black
	u8g2_SetFontMode(&m1_u8g2, U8G2_FONT_MODE_SOLID); // U8G2_FONT_MODE_SOLID, U8G2_FONT_MODE_TRANSPARENT
} // void m1_lcd_cleardisplay(void)
