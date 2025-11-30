#include <stdio.h>
#include <stdint.h>
#include "hello_test.h"
#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"
// #include "hiview_log.h"


#define TASK_DELAY_TICKS     1000   // 1秒延迟
#define TASK_STACK_SIZE      0x1000
#define TASK_PRI             6

void HelloTaskEntry(void) {
    typedef union{
        uint32_t value;
        uint8_t bytes[4];
    } endian_test_t;

    endian_test_t test;
    test.value = 0x12345678;

    if (test.bytes[0] == 0x78) {
        printf("HelloApp: Little Endian Detected\n");
    } else if (test.bytes[0] == 0x12) {
        printf("HelloApp: Big Endian Detected\n");
    } else {
        printf("HelloApp: Unknown Endian\n");
    }
}

void HelloTaskInit(void) {
    // 注册应用模块 在hiview_log.c中已经注册过，此处可注释掉
    // HiLogRegisterModule(HILOG_MODULE_HELLOTEST, "HELLOTEST");

    // HILOG_INFO(HILOG_MODULE_HELLOTEST, "Module HELLOTEST initialized successfully");

    unsigned int ret;
    unsigned int taskID;
    TSK_INIT_PARAM_S task = { 0 };
    task.pfnTaskEntry = (TSK_ENTRY_FUNC)HelloTaskEntry;
    task.uwStackSize  = TASK_STACK_SIZE;
    task.pcName       = "HelloTaskEntry";
    task.usTaskPrio   = TASK_PRI;
    
    ret = LOS_TaskCreate(&taskID, &task);
    if (ret != LOS_OK) {
        printf("HelloApp task create failed: 0x%X\n", ret);
        // HILOG_INFO(HILOG_MODULE_HELLOTEST, "HelloApp task create failed");
    }
}

// APP_FEATURE_INIT(HelloAppInit);