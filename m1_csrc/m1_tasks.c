/* See COPYING.txt for license details. */

/*
*
* m1_tasks.c
*
* Task functions for M1
*
* M1 Project
*
*/


/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "m1_tasks.h"
#include "m1_sdcard.h"
#include "lfrfid.h"
//#include "m1_nfc.h"
#include "nfc_driver.h"
#include "m1_compile_cfg.h"
#include "m1_menu.h"
#include "m1_crash_log.h"
#include "m1_log_debug.h"
#include "FreeRTOS.h"
#include "task.h"
#ifdef M1_APP_RPC_ENABLE
#include "m1_rpc.h"
#endif

/*************************** D E F I N E S ************************************/

#define M1_LOGDB_TAG	"Tasks"

#define MAIN_QUEUE_ITEMS_MAX_N				256
#define SDCARD_DET_QUEUE_ITEMS_MAX_N		10

//************************** C O N S T A N T **********************************/

//************************** S T R U C T U R E S *******************************

/***************************** V A R I A B L E S ******************************/

extern IWDG_HandleTypeDef hiwdg;

//extern osThreadId_t dummytaskHandle;
osTimerId_t dummyTimerHandle;
const osTimerAttr_t dumyTimer_attributes = {
  .name = "dummyTimer"
};

QueueHandle_t	main_q_hdl;
QueueHandle_t	sdcard_det_q_hdl;
TaskHandle_t	runonce_task_hdl;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

void m1_tasks_init(void);
void vApplicationIdleHook(void);
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName);
void vApplicationMallocFailedHook(void);

void m1_dummy_task(void *argument);
void m1_dummytimer_task(void *argument);
void m1_runonce_task_handler(void *param);
/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

/*============================================================================*/
/*
 * This function initializes and creates default tasks for the system
 * after power up.
 */
/*============================================================================*/
void m1_tasks_init(void)
{
	BaseType_t ret;
	size_t free_heap;

	main_q_hdl = xQueueCreate(MAIN_QUEUE_ITEMS_MAX_N, sizeof(S_M1_Main_Q_t));
	assert(main_q_hdl != NULL);

	sdcard_det_q_hdl = xQueueCreate(SDCARD_DET_QUEUE_ITEMS_MAX_N, sizeof(S_M1_SdCard_Q_t));
	assert(sdcard_det_q_hdl != NULL);

	dummyTimerHandle = osTimerNew(m1_dummytimer_task, osTimerOnce, NULL, &dumyTimer_attributes);

	ret = xTaskCreate(system_periodic_task, "system_periodic_task_n", M1_TASK_STACK_SIZE_DEFAULT, NULL, TASK_PRIORITY_SYSTEM_TASK_HANDLER, &system_task_hdl);
	assert(ret==pdPASS);
	assert(system_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize(); // xPortGetMinimumEverFreeHeapSize()
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(sdcard_detection_task, "sdcard_detection_task_n", M1_TASK_STACK_SIZE_DEFAULT, NULL, TASK_PRIORITY_SDCARD_HANDLER, &sdcard_task_hdl);
	assert(ret==pdPASS);
	assert(system_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(menu_main_handler_task, "menu_main_handler_task_n", M1_TASK_STACK_SIZE_1024/*M1_TASK_STACK_SIZE_DEFAULT*/, NULL, TASK_PRIORITY_MENU_MAIN_HANDLER, &menu_main_handler_task_hdl);
	assert(ret==pdPASS);
	assert(menu_main_handler_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(subfunc_handler_task, "subfunc_handler_task_n", M1_TASK_STACK_SIZE_4096, NULL, TASK_PRIORITY_SUBFUNC_HANDLER, &subfunc_handler_task_hdl);
	assert(ret==pdPASS);
	assert(subfunc_handler_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(log_db_handler_task, "log_db_handler_task_n", M1_TASK_STACK_SIZE_1024, NULL, TASK_PRIORITY_LOG_DB_HANDLER, &log_db_task_hdl);
	assert(ret==pdPASS);
	assert(log_db_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(idle_handler_task, "idle_handler_task_n", M1_TASK_STACK_SIZE_0512, NULL, TASK_PRIORITY_IDLE_HANDLER, &idle_task_hdl);
	assert(ret==pdPASS);
	assert(idle_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(m1_runonce_task_handler, "m1_runonce_task_n", M1_TASK_STACK_SIZE_0512, NULL, TASK_PRIORITY_RUNONCE_TASK_HANDLER, &runonce_task_hdl);
	assert(ret==pdPASS);
	assert(runonce_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

	ret = xTaskCreate(vSer2UsbTask, "m1_ser2usb_task_n", M1_TASK_STACK_SIZE_2048, NULL, TASK_PRIORITY_RUNONCE_TASK_HANDLER, &usb2ser_task_hdl);
	assert(ret==pdPASS);
	assert(usb2ser_task_hdl!=NULL);
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);

#ifdef M1_APP_RPC_ENABLE
	/* Initialize the RPC subsystem (creates the RPC task internally) */
	m1_rpc_init();
	free_heap = xPortGetFreeHeapSize();
	assert(free_heap >= M1_LOW_FREE_HEAP_WARNING_SIZE);
#endif
} // void m1_tasks_init(void)



/*============================================================================*/
/*
 * This task is called by the OS when the system is in idle state.
 * configUSE_IDLE_HOOK must be set to 1 in FreeRTOSConfig.h
 */
/*============================================================================*/
void vApplicationIdleHook(void)
{
	__WFI();
} // void vApplicationIdleHook(void)



/*============================================================================*/
/*
* The application stack overflow hook is called when a stack overflow is detected for a task.
*
* Details on stack overflow detection can be found here: https://www.FreeRTOS.org/Stacks-and-stack-overflow-checking.html
*
* configCHECK_FOR_STACK_OVERFLOW must be defined (1 or 2) in FreeRTOSConfig.h
*
* @param xTask the task that just exceeded its stack boundaries.
* @param pcTaskName A character string containing the name of the offending task.
*/
/*============================================================================*/

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
	(void)xTask;
	/* Stack is corrupted. Cannot rely on M1_LOG_E (allocates) or any FreeRTOS
	 * API that walks task state. Capture name + reset via BKPSRAM. */
	m1_crash_record_simple(M1_CRASH_STACK_OVF, pcTaskName);
} // void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)



/*============================================================================*/
/*
* The application heap failure hook is called when malloc failure is detected for a task.
*
* configUSE_MALLOC_FAILED_HOOK in FreeRTOSConfig.h
*/
/*============================================================================*/
void vApplicationMallocFailedHook(void)
{
	/* Many call sites assume non-NULL pvPortMalloc and would deref NULL on
	 * the next instruction. Capture and reset rather than continue. */
	m1_crash_record_simple(M1_CRASH_MALLOC_FAIL, NULL);
} // void vApplicationMallocFailedHook (void)



/*============================================================================*/
/*
* This task does nothing. It's defined as a dummy task to avoid compile error!
*
*/
/*============================================================================*/
void m1_dummy_task(void *argument)
{
  /* USER CODE BEGIN defaultTask */
  /* Infinite loop */
  for(;;)
  {
	  osDelay(portMAX_DELAY);
  }
  /* USER CODE END defaultTask */
} // void m1_dummy_task(void *argument)



/*============================================================================*/
/*
* This task does nothing. It's defined as a dummy task to avoid compile error!
*
*/
/*============================================================================*/
void m1_dummytimer_task(void *argument)
{
  /* USER CODE BEGIN m1_dummytimer_task */
	/* Infinite loop */
	for(;;)
	{
		osDelay(portMAX_DELAY);
	}
  /* USER CODE END m1_dummytimer_task */
} // void m1_dummytimer_task(void *argument)



/*============================================================================*/
/*
* This task runs once after power up
*
*/
/*============================================================================*/
void m1_runonce_task_handler(void *param)
{
	//m1_led_indicator_on(NULL);
	vTaskDelete(NULL); // Delete this task
} // void m1_runonce_task_handler(void *param)



/*============================================================================*/
/*
 * Stack high-water-mark instrumentation.
 *
 * audit 07 m1_tasks.c:97-127 — stack sizes were uniformly chosen at
 * 1024/2048 32-bit words across every task.  subfunc_handler_task is at
 * 4096 words = 16 KB and is suspected ~4x over-provisioned.  Reduce the
 * over-provisioning carefully by measuring real usage first.
 *
 * uxTaskGetStackHighWaterMark returns "minimum unused words ever observed"
 * for a task; a low value is danger (close to overflow), a large value is
 * waste.  Print the table to the debug log (and optionally also to a
 * caller-supplied buffer for CLI use) so we can iterate stack sizing
 * without flying blind.
 *
 * No stack reductions are committed in this change — the audit
 * specifically noted "leave stack reduction for a follow-up after
 * confirmed measurements".
 */
/*============================================================================*/
size_t m1_perf_dump_task_stacks(char *out_buf, size_t out_size)
{
    static const char *header = "task                            prio  hwm-words  hwm-bytes\r\n";
    size_t  total_written = 0;
    UBaseType_t n_tasks   = uxTaskGetNumberOfTasks();
    TaskStatus_t *snap    = NULL;
    UBaseType_t snap_n    = 0;
    UBaseType_t i;
    char line[96];
    int n;

#define APPEND(s, len) do {                                       \
        if (out_buf && (total_written + (len)) < out_size) {      \
            memcpy(out_buf + total_written, (s), (len));          \
            out_buf[total_written + (len)] = '\0';                \
        }                                                         \
        total_written += (len);                                   \
    } while (0)

    M1_LOG_I(M1_LOGDB_TAG, "%s", header);
    APPEND(header, strlen(header));

    if (n_tasks == 0)
        return total_written;

    /* uxTaskGetSystemState requires configUSE_TRACE_FACILITY=1; the project
     * currently has it OFF (FreeRTOSConfig.h:77).  When trace is OFF we fall
     * back to walking the named handles we know about. */
#if (configUSE_TRACE_FACILITY == 1)
    snap = (TaskStatus_t *)pvPortMalloc(sizeof(TaskStatus_t) * n_tasks);
    if (snap)
    {
        snap_n = uxTaskGetSystemState(snap, n_tasks, NULL);
        for (i = 0; i < snap_n; i++)
        {
            n = snprintf(line, sizeof(line),
                         "%-32s  %3lu  %9lu  %9lu\r\n",
                         snap[i].pcTaskName,
                         (unsigned long)snap[i].uxCurrentPriority,
                         (unsigned long)snap[i].usStackHighWaterMark,
                         (unsigned long)snap[i].usStackHighWaterMark * 4UL);
            if (n > 0)
            {
                M1_LOG_I(M1_LOGDB_TAG, "%s", line);
                APPEND(line, (size_t)n);
            }
        }
        vPortFree(snap);
    }
#else
    /* Fallback: enumerate the few known handles we exported externally. */
    extern TaskHandle_t system_task_hdl;
    extern TaskHandle_t sdcard_task_hdl;
    extern TaskHandle_t menu_main_handler_task_hdl;
    extern TaskHandle_t subfunc_handler_task_hdl;
    extern TaskHandle_t log_db_task_hdl;
    extern TaskHandle_t idle_task_hdl;
    extern TaskHandle_t usb2ser_task_hdl;
    static TaskHandle_t * const named_tasks[] = {
        &system_task_hdl,
        &sdcard_task_hdl,
        &menu_main_handler_task_hdl,
        &subfunc_handler_task_hdl,
        &log_db_task_hdl,
        &idle_task_hdl,
        &usb2ser_task_hdl,
    };
    static const char * const named_names[] = {
        "system_periodic_task_n",
        "sdcard_detection_task_n",
        "menu_main_handler_task_n",
        "subfunc_handler_task_n",
        "log_db_handler_task_n",
        "idle_handler_task_n",
        "m1_ser2usb_task_n",
    };
    for (i = 0; i < (sizeof(named_tasks) / sizeof(named_tasks[0])); i++)
    {
        TaskHandle_t hdl = (named_tasks[i] != NULL) ? *named_tasks[i] : NULL;
        UBaseType_t hwm   = (hdl != NULL) ? uxTaskGetStackHighWaterMark(hdl) : 0;
        UBaseType_t prio  = (hdl != NULL) ? uxTaskPriorityGet(hdl) : 0;
        n = snprintf(line, sizeof(line),
                     "%-32s  %3lu  %9lu  %9lu\r\n",
                     named_names[i],
                     (unsigned long)prio,
                     (unsigned long)hwm,
                     (unsigned long)hwm * 4UL);
        if (n > 0)
        {
            M1_LOG_I(M1_LOGDB_TAG, "%s", line);
            APPEND(line, (size_t)n);
        }
    }
    (void)snap;
    (void)snap_n;
#endif /* configUSE_TRACE_FACILITY */

#undef APPEND
    return total_written;
}
