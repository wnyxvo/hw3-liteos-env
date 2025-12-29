// vtpm_test_main.c
#include "vtpms_test.h"
#include "los_config.h"

// 定义任务栈
STATIC UINT8 g_lowTaskStack1[LOW_PRIORITY_STACK_SIZE];
STATIC UINT8 g_lowTaskStack2[LOW_PRIORITY_STACK_SIZE];
STATIC UINT8 g_lowTaskStack3[LOW_PRIORITY_STACK_SIZE];
STATIC UINT8 g_highTaskStack[HIGH_PRIORITY_STACK_SIZE];
STATIC UINT8 g_monitorTaskStack[MONITOR_STACK_SIZE];

// 内存池（如果需要动态内存）
#define TEST_MEM_POOL_SIZE 0x2000
STATIC UINT8 g_testMemPool[TEST_MEM_POOL_SIZE];

// 初始化系统资源
UINT32 InitTestResources(VOID)
{
    UINT32 ret;
    
    // 初始化内存池
    ret = LOS_MemInit(g_testMemPool, TEST_MEM_POOL_SIZE);
    if (ret != LOS_OK) {
        printf("Memory pool init failed: 0x%x\n", ret);
        return ret;
    }
    
    printf("Test resources initialized\n");
    return LOS_OK;
}

// 主测试函数
UINT32 VtpmSchedulerTest(VOID)
{
    UINT32 ret;
    
    // 1. 初始化资源
    ret = InitTestResources();
    if (ret != LOS_OK) {
        return ret;
    }
    
    // 2. 创建任务
    ret = CreateVtpmTasks();
    if (ret != LOS_OK) {
        printf("Failed to create vtpm tasks: 0x%x\n", ret);
        return ret;
    }
    
    // 3. 运行测试一段时间
    printf("\nRunning vTPM scheduler test for 10 seconds...\n");
    LOS_TaskDelay(10000);  // 运行10秒（10000 ticks）
    
    // 4. 停止测试
    StopVtpmTasks();
    
    return LOS_OK;
}

// 在app_init中调用测试
VOID app_init(VOID)
{
    printf("vTPM Scheduler Test Application\n");
    
    UINT32 ret = VtpmSchedulerTest();
    if (ret != LOS_OK) {
        printf("vTPM scheduler test failed: 0x%x\n", ret);
    } else {
        printf("vTPM scheduler test completed successfully\n");
    }
}