/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    stm32h5xx_it.c
  * @brief   Interrupt Service Routines.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32h5xx_it.h"
#include "m1_crash_log.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* Common entry called from naked fault stubs below. r0 = stacked frame
 * pointer (MSP or PSP at moment of fault), r1 = fault kind, r2 = exc_return.
 * Records fault state to BKPSRAM and resets the device. */
__attribute__((used))
static void m1_fault_dispatch(uint32_t *frame_ptr, uint32_t kind, uint32_t exc_return)
{
    m1_crash_frame_t f;
    if (frame_ptr) {
        f.r0  = frame_ptr[0];
        f.r1  = frame_ptr[1];
        f.r2  = frame_ptr[2];
        f.r3  = frame_ptr[3];
        f.r12 = frame_ptr[4];
        f.lr  = frame_ptr[5];
        f.pc  = frame_ptr[6];
        f.psr = frame_ptr[7];
    } else {
        f.r0 = f.r1 = f.r2 = f.r3 = 0;
        f.r12 = f.lr = f.pc = f.psr = 0;
    }
    m1_crash_record_fault((m1_crash_kind_t)kind, &f, exc_return);
}

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/
extern IWDG_HandleTypeDef hiwdg;
extern RTC_HandleTypeDef hrtc;
extern SD_HandleTypeDef hsd1;
extern TIM_HandleTypeDef htim6;

/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
  /* USER CODE BEGIN NonMaskableInt_IRQn 0 */

    /* Check for flash double-ECC error (ECCD) */
    if (FLASH->ECCDETR & FLASH_ECCR_ECCD)
    {
        /* Clear the ECCD flag (write-1-to-clear) */
        SET_BIT(FLASH->ECCDETR, FLASH_ECCR_ECCD);

        /* If a protected flash read is in progress, skip the faulting
         * ldr.w instruction (4 bytes) and set the fault flag so the
         * caller knows the read failed. */
        extern volatile bool g_flash_read_protected;
        extern volatile bool g_flash_read_faulted;

        if (g_flash_read_protected)
        {
            g_flash_read_faulted = true;

            /* Determine which stack the faulting code was using (PSP or MSP)
             * and advance the stacked PC by 4 to skip the ldr.w instruction.
             * EXC_RETURN bit 2: 0 = MSP, 1 = PSP.
             * Stacked PC is at offset 24 (frame[6]) in the exception frame. */
            __ASM volatile (
                "TST   LR, #4       \n"   /* Test bit 2 of EXC_RETURN  */
                "ITE   NE           \n"
                "MRSNE R0, PSP      \n"   /* FreeRTOS task: frame on PSP */
                "MRSEQ R0, MSP      \n"   /* Handler/init: frame on MSP */
                "LDR   R1, [R0, #24]\n"   /* R1 = stacked PC            */
                "ADDS  R1, R1, #4   \n"   /* Skip 4-byte ldr.w          */
                "STR   R1, [R0, #24]\n"   /* Write back                 */
                ::: "r0", "r1", "memory"
            );
            return;
        }

        /* Unprotected flash read — fall through to default handler */
    }

  /* USER CODE END NonMaskableInt_IRQn 0 */
  /* USER CODE BEGIN NonMaskableInt_IRQn 1 */
  /* If we reach here, something faulted via NMI without the ECC-recovery
   * path consuming it. Capture and reset rather than wedging on while(1). */
  m1_crash_record_simple(M1_CRASH_NMI, NULL);
  /* USER CODE END NonMaskableInt_IRQn 1 */
}

/* HardFault — capture stacked frame from MSP or PSP per EXC_RETURN bit 2. */
__attribute__((naked))
void HardFault_Handler(void)
{
    __asm volatile (
        "tst   lr, #4              \n"
        "ite   eq                  \n"
        "mrseq r0, msp             \n"
        "mrsne r0, psp             \n"
        "mov   r1, %0              \n"
        "mov   r2, lr              \n"
        "b     m1_fault_dispatch   \n"
        :: "i"(M1_CRASH_HARDFAULT)
        : "r0", "r1", "r2"
    );
}

__attribute__((naked))
void MemManage_Handler(void)
{
    __asm volatile (
        "tst   lr, #4              \n"
        "ite   eq                  \n"
        "mrseq r0, msp             \n"
        "mrsne r0, psp             \n"
        "mov   r1, %0              \n"
        "mov   r2, lr              \n"
        "b     m1_fault_dispatch   \n"
        :: "i"(M1_CRASH_MEMMANAGE)
        : "r0", "r1", "r2"
    );
}

__attribute__((naked))
void BusFault_Handler(void)
{
    __asm volatile (
        "tst   lr, #4              \n"
        "ite   eq                  \n"
        "mrseq r0, msp             \n"
        "mrsne r0, psp             \n"
        "mov   r1, %0              \n"
        "mov   r2, lr              \n"
        "b     m1_fault_dispatch   \n"
        :: "i"(M1_CRASH_BUSFAULT)
        : "r0", "r1", "r2"
    );
}

__attribute__((naked))
void UsageFault_Handler(void)
{
    __asm volatile (
        "tst   lr, #4              \n"
        "ite   eq                  \n"
        "mrseq r0, msp             \n"
        "mrsne r0, psp             \n"
        "mov   r1, %0              \n"
        "mov   r2, lr              \n"
        "b     m1_fault_dispatch   \n"
        :: "i"(M1_CRASH_USAGEFAULT)
        : "r0", "r1", "r2"
    );
}

/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
  /* USER CODE BEGIN DebugMonitor_IRQn 0 */

  /* USER CODE END DebugMonitor_IRQn 0 */
  /* USER CODE BEGIN DebugMonitor_IRQn 1 */

  /* USER CODE END DebugMonitor_IRQn 1 */
}

/******************************************************************************/
/* STM32H5xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32h5xx.s).                    */
/******************************************************************************/

/**
  * @brief This function handles RTC non-secure interrupt.
  */
void RTC_IRQHandler(void)
{
  /* USER CODE BEGIN RTC_IRQn 0 */

  /* USER CODE END RTC_IRQn 0 */
  HAL_RTCEx_WakeUpTimerIRQHandler(&hrtc);
  /* USER CODE BEGIN RTC_IRQn 1 */

  /* USER CODE END RTC_IRQn 1 */
}

/**
  * @brief This function handles IWDG global interrupt.
  */
void IWDG_IRQHandler(void)
{
  /* USER CODE BEGIN IWDG_IRQn 0 */

  /* USER CODE END IWDG_IRQn 0 */
  HAL_IWDG_IRQHandler(&hiwdg);
  /* USER CODE BEGIN IWDG_IRQn 1 */

  /* USER CODE END IWDG_IRQn 1 */
}

/**
  * @brief This function handles TIM6 global interrupt.
  */
void TIM6_IRQHandler(void)
{
  /* USER CODE BEGIN TIM6_IRQn 0 */

  /* USER CODE END TIM6_IRQn 0 */
  HAL_TIM_IRQHandler(&htim6);
  /* USER CODE BEGIN TIM6_IRQn 1 */

  /* USER CODE END TIM6_IRQn 1 */
}

/**
  * @brief This function handles SDMMC1 global interrupt.
  */
void SDMMC1_IRQHandler(void)
{
  /* USER CODE BEGIN SDMMC1_IRQn 0 */

  /* USER CODE END SDMMC1_IRQn 0 */
  HAL_SD_IRQHandler(&hsd1);
  /* USER CODE BEGIN SDMMC1_IRQn 1 */

  /* USER CODE END SDMMC1_IRQn 1 */
}

/* USER CODE BEGIN 1 */
/**
  * @brief This function handles RTC non-secure interrupt.
  */
void EXTI0_IRQHandler(void)
{
  /* USER CODE BEGIN RTC_IRQn 0 */

  /* USER CODE END RTC_IRQn 0 */
  HAL_EXTI_IRQHandler(&H_EXTI_0);
  /* USER CODE BEGIN RTC_IRQn 1 */

  /* USER CODE END RTC_IRQn 1 */
}
/* USER CODE END 1 */
