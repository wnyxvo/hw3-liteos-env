#include <stdio.h>
// #include "math_ops.h"
#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"

#define TASK_STACK_SIZE      0x1000
#define TASK_PRI             6

void MathTestTask(void *arg) {
    (void)arg;
    
    printf("\n==== Math Library Test ====\n");
    
    // 测试加法
    int result = add(5, 3);
    printf("5 + 3 = %d\n", result);
    
    // 测试减法
    result = subtract(10, 4);
    printf("10 - 4 = %d\n", result);
    
    // 测试乘法
    result = multiply(6, 7);
    printf("6 * 7 = %d\n", result);
    
    // 测试除法
    float fresult = divide(20, 5);
    printf("20 / 5 = %.2f\n", fresult);
    
    // 测试除零保护
    fresult = divide(10, 0);
    printf("10 / 0 = %.2f (should be 0.00)\n", fresult);
    
    printf("Math tests completed!\n");
}

void MathTestApp(void) {
    unsigned int ret;
    unsigned int taskID;
    TSK_INIT_PARAM_S task = { 0 };
    task.pfnTaskEntry = (TSK_ENTRY_FUNC)MathTestTask;
    task.uwStackSize  = TASK_STACK_SIZE;
    task.pcName       = "MathTestTask";
    task.usTaskPrio   = TASK_PRI;
    
    ret = LOS_TaskCreate(&taskID, &task);
    if (ret != LOS_OK) {
        printf("MathTestApp task create failed: 0x%X\n", ret);
        // HILOG_INFO(HILOG_MODULE_HELLOTEST, "HelloApp task create failed");
    }
}

// APP_FEATURE_INIT(MathTestApp);