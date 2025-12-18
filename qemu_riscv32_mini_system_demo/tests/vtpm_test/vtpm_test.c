// vtpms_test.c
#include "vtpms_test.h"

// 全局任务统计
#define LOW_PRIORITY_TASK_NUM 3
#define HIGH_PRIORITY_TASK_NUM 1
#define MONITOR_TASK_NUM 1
#define TOTAL_TASK_NUM (LOW_PRIORITY_TASK_NUM + HIGH_PRIORITY_TASK_NUM + MONITOR_TASK_NUM)

// 任务栈大小
#define LOW_PRIORITY_STACK_SIZE 0x800
#define HIGH_PRIORITY_STACK_SIZE 0x1000
#define MONITOR_STACK_SIZE 0x1000

// 任务优先级定义
#define LOW_PRIORITY 20      // 低优先级
#define HIGH_PRIORITY 5      // 高优先级
#define MONITOR_PRIORITY 2   // 监控任务优先级（最高）

// 全局变量
static TaskStat g_lowTasks[LOW_PRIORITY_TASK_NUM];
static TaskStat g_highTask;
static TaskStat g_monitorTask;
static volatile BOOL g_taskRunning = TRUE;
static volatile UINT32 g_contextSwitchCount = 0;
static volatile UINT32 g_lastTickCount = 0;
static volatile UINT32 g_totalTicks = 0;

// 统计上下文切换
VOID TaskSwitchHook(UINT32 taskId)
{
    g_contextSwitchCount++;
    g_lastTickCount = LOS_TickCountGet();
}

// 低优先级任务入口函数
VOID *LowPriorityTaskEntry(UINTPTR arg)
{
    TaskStat *stat = (TaskStat *)arg;
    UINT32 ret;
    UINT32 taskId = LOS_CurTaskIDGet();
    
    if (stat) {
        stat->taskId = taskId;
    }
    
    printf("[LowTask%d] Task started, ID: 0x%x, Prio: %d\n", 
           (int)(arg + 1), taskId, LOW_PRIORITY);
    
    while (g_taskRunning) {
        // 记录调度开始时间
        UINT32 startTick = LOS_TickCountGet();
        
        // 模拟计算任务
        volatile UINT32 i, j = 0;
        for (i = 0; i < 1000; i++) {
            j += i;
        }
        
        // 记录调度结束时间
        UINT32 endTick = LOS_TickCountGet();
        
        if (stat) {
            stat->scheduleCount++;
            if (stat->lastRunTick > 0) {
                UINT32 interval = startTick - stat->lastRunTick;
                if (interval > 0) {
                    printf("[LowTask%d] #%d Scheduled, Interval: %u ticks, "
                           "RunTime: %u ticks\n", 
                           (int)((UINTPTR)stat - (UINTPTR)g_lowTasks) / sizeof(TaskStat) + 1,
                           stat->scheduleCount, 
                           interval,
                           endTick - startTick);
                }
            }
            stat->lastRunTick = startTick;
            stat->totalRunTicks += (endTick - startTick);
        }
        
        // 主动让出CPU
        ret = LOS_TaskDelay(10);  // 延时10个tick
        if (ret != LOS_OK) {
            printf("[LowTask%d] Delay failed: 0x%x\n", 
                   (int)((UINTPTR)stat - (UINTPTR)g_lowTasks) / sizeof(TaskStat) + 1, 
                   ret);
        }
    }
    
    printf("[LowTask%d] Task exiting\n", 
           (int)((UINTPTR)stat - (UINTPTR)g_lowTasks) / sizeof(TaskStat) + 1);
    
    return NULL;
}

// 高优先级任务入口函数
VOID *HighPriorityTaskEntry(UINTPTR arg)
{
    TaskStat *stat = (TaskStat *)arg;
    UINT32 ret;
    UINT32 taskId = LOS_CurTaskIDGet();
    
    if (stat) {
        stat->taskId = taskId;
    }
    
    printf("[HighTask] Task started, ID: 0x%x, Prio: %d\n", 
           taskId, HIGH_PRIORITY);
    
    UINT32 executionCount = 0;
    while (g_taskRunning && executionCount < 100) {  // 限制执行次数
        // 记录调度开始时间
        UINT32 startTick = LOS_TickCountGet();
        
        // 模拟紧急处理任务
        printf("[HighTask] Executing emergency task...\n");
        volatile UINT32 k, l = 0;
        for (k = 0; k < 500; k++) {
            l += k * 2;
        }
        
        // 记录调度结束时间
        UINT32 endTick = LOS_TickCountGet();
        
        if (stat) {
            stat->scheduleCount++;
            if (stat->lastRunTick > 0) {
                UINT32 interval = startTick - stat->lastRunTick;
                printf("[HighTask] #%d Scheduled, Interval: %u ticks, "
                       "RunTime: %u ticks\n", 
                       stat->scheduleCount, interval, endTick - startTick);
            }
            stat->lastRunTick = startTick;
            stat->totalRunTicks += (endTick - startTick);
        }
        
        executionCount++;
        
        // 高优先级任务也适当延时，让低优先级任务有机会运行
        ret = LOS_TaskDelay(5);  // 延时5个tick
        if (ret != LOS_OK) {
            printf("[HighTask] Delay failed: 0x%x\n", ret);
        }
    }
    
    printf("[HighTask] Task completed %d executions\n", executionCount);
    
    return NULL;
}

// 监控任务入口函数
VOID *MonitorTaskEntry(UINTPTR arg)
{
    TaskStat *stat = (TaskStat *)arg;
    UINT32 taskId = LOS_CurTaskIDGet();
    
    if (stat) {
        stat->taskId = taskId;
    }
    
    printf("[Monitor] Task started, ID: 0x%x, Prio: %d\n", 
           taskId, MONITOR_PRIORITY);
    
    UINT32 lastSwitchCount = 0;
    UINT32 lastTotalTicks = 0;
    
    while (g_taskRunning) {
        // 计算统计信息
        UINT32 currentTicks = LOS_TickCountGet();
        UINT32 switchDiff = g_contextSwitchCount - lastSwitchCount;
        UINT32 tickDiff = currentTicks - lastTotalTicks;
        
        if (tickDiff >= 100) {  // 每100个tick报告一次
            printf("\n[Monitor] ======== System Statistics ========\n");
            printf("[Monitor] Total Ticks: %u\n", currentTicks);
            printf("[Monitor] Context Switches: %u (+%u)\n", 
                   g_contextSwitchCount, switchDiff);
            
            if (tickDiff > 0) {
                printf("[Monitor] Switch Frequency: %.2f switches/tick\n", 
                       (float)switchDiff / tickDiff);
            }
            
            // 计算低优先级任务统计
            UINT32 lowTotalSchedules = 0;
            UINT32 lowTotalTicks = 0;
            for (int i = 0; i < LOW_PRIORITY_TASK_NUM; i++) {
                lowTotalSchedules += g_lowTasks[i].scheduleCount;
                lowTotalTicks += g_lowTasks[i].totalRunTicks;
            }
            
            printf("[Monitor] Low Priority Tasks: %d schedules, %u total ticks\n", 
                   lowTotalSchedules, lowTotalTicks);
            
            // 计算高优先级任务统计
            printf("[Monitor] High Priority Task: %d schedules, %u total ticks\n", 
                   g_highTask.scheduleCount, g_highTask.totalRunTicks);
            
            // 计算时间片轮转时间（估算）
            if (lowTotalSchedules > 0 && lowTotalTicks > 0) {
                float avgSliceTime = (float)lowTotalTicks / lowTotalSchedules;
                printf("[Monitor] Estimated Time Slice: %.2f ticks\n", avgSliceTime);
                
                // 假设系统tick为10ms
                printf("[Monitor] Estimated Time Slice: %.2f ms\n", avgSliceTime * 10);
            }
            
            // 计算CPU利用率
            UINT32 totalRunTicks = lowTotalTicks + g_highTask.totalRunTicks;
            if (tickDiff > 0) {
                float cpuUsage = (float)totalRunTicks * 100 / tickDiff;
                printf("[Monitor] CPU Usage: %.2f%%\n", cpuUsage);
            }
            
            lastSwitchCount = g_contextSwitchCount;
            lastTotalTicks = currentTicks;
        }
        
        // 监控任务休眠一段时间
        LOS_TaskDelay(50);
    }
    
    printf("[Monitor] Task exiting\n");
    return NULL;
}

// 创建测试任务
UINT32 CreateVtpmTasks(VOID)
{
    UINT32 ret;
    TSK_INIT_PARAM_S taskInitParam = {0};
    
    printf("\n======= vTPM Multi-Instance Test Start =======\n");
    
    // 注册任务切换钩子
    ret = LOS_TaskSwitchHookReg(TaskSwitchHook);
    if (ret != LOS_OK) {
        printf("Failed to register task switch hook: 0x%x\n", ret);
    }
    
    // 1. 创建3个低优先级任务（模拟多个vTPM实例）
    for (int i = 0; i < LOW_PRIORITY_TASK_NUM; i++) {
        // 初始化任务统计
        (VOID)memset_s(&g_lowTasks[i], sizeof(TaskStat), 0, sizeof(TaskStat));
        (VOID)snprintf_s(g_lowTasks[i].name, sizeof(g_lowTasks[i].name), 
                        sizeof(g_lowTasks[i].name) - 1, "LowVtpm%d", i + 1);
        g_lowTasks[i].priority = LOW_PRIORITY;
        
        // 设置任务参数
        taskInitParam.usTaskPrio = LOW_PRIORITY;
        taskInitParam.pcName = g_lowTasks[i].name;
        taskInitParam.uwStackSize = LOW_PRIORITY_STACK_SIZE;
        taskInitParam.pfnTaskEntry = (TSK_ENTRY_FUNC)LowPriorityTaskEntry;
        taskInitParam.uwArg = (UINTPTR)&g_lowTasks[i];
        
        ret = LOS_TaskCreate(&g_lowTasks[i].taskId, &taskInitParam);
        if (ret != LOS_OK) {
            printf("Failed to create low priority task %d: 0x%x\n", i + 1, ret);
            return ret;
        }
        printf("Created low priority task %d: ID=0x%x\n", 
               i + 1, g_lowTasks[i].taskId);
    }
    
    // 2. 创建1个高优先级任务（模拟TPM调度器或紧急任务）
    (VOID)memset_s(&g_highTask, sizeof(TaskStat), 0, sizeof(TaskStat));
    (VOID)strcpy_s(g_highTask.name, sizeof(g_highTask.name), "HighVtpm");
    g_highTask.priority = HIGH_PRIORITY;
    
    taskInitParam.usTaskPrio = HIGH_PRIORITY;
    taskInitParam.pcName = g_highTask.name;
    taskInitParam.uwStackSize = HIGH_PRIORITY_STACK_SIZE;
    taskInitParam.pfnTaskEntry = (TSK_ENTRY_FUNC)HighPriorityTaskEntry;
    taskInitParam.uwArg = (UINTPTR)&g_highTask;
    
    ret = LOS_TaskCreate(&g_highTask.taskId, &taskInitParam);
    if (ret != LOS_OK) {
        printf("Failed to create high priority task: 0x%x\n", ret);
        return ret;
    }
    printf("Created high priority task: ID=0x%x\n", g_highTask.taskId);
    
    // 3. 创建监控任务
    (VOID)memset_s(&g_monitorTask, sizeof(TaskStat), 0, sizeof(TaskStat));
    (VOID)strcpy_s(g_monitorTask.name, sizeof(g_monitorTask.name), "VtpmMonitor");
    g_monitorTask.priority = MONITOR_PRIORITY;
    
    taskInitParam.usTaskPrio = MONITOR_PRIORITY;
    taskInitParam.pcName = g_monitorTask.name;
    taskInitParam.uwStackSize = MONITOR_STACK_SIZE;
    taskInitParam.pfnTaskEntry = (TSK_ENTRY_FUNC)MonitorTaskEntry;
    taskInitParam.uwArg = (UINTPTR)&g_monitorTask;
    
    ret = LOS_TaskCreate(&g_monitorTask.taskId, &taskInitParam);
    if (ret != LOS_OK) {
        printf("Failed to create monitor task: 0x%x\n", ret);
        return ret;
    }
    printf("Created monitor task: ID=0x%x\n", g_monitorTask.taskId);
    
    printf("======= vTPM Multi-Instance Test Running =======\n");
    return LOS_OK;
}

// 停止所有测试任务
VOID StopVtpmTasks(VOID)
{
    printf("\n======= Stopping vTPM Test Tasks =======\n");
    g_taskRunning = FALSE;
    
    // 等待任务自然退出
    LOS_TaskDelay(1000);
    
    // 打印最终统计
    printf("\n======= Final Statistics =======\n");
    printf("Total Context Switches: %u\n", g_contextSwitchCount);
    
    for (int i = 0; i < LOW_PRIORITY_TASK_NUM; i++) {
        printf("LowTask%d: %u schedules, %u total run ticks\n", 
               i + 1, g_lowTasks[i].scheduleCount, g_lowTasks[i].totalRunTicks);
    }
    
    printf("HighTask: %u schedules, %u total run ticks\n", 
           g_highTask.scheduleCount, g_highTask.totalRunTicks);
    
    printf("======= vTPM Multi-Instance Test Complete =======\n");
}