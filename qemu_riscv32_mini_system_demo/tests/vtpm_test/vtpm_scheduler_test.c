// vtpms_scheduler_test.c
#include "los_task.h"
#include "los_memory.h"
#include "los_tick.h"
#include "los_atomic.h"
#include "securec.h"
#include "stdio.h"

// 配置常量
#define TICKS_PER_SECOND 100
#define TIMESLICE_TICKS 20000
#define TIMESLICE_MS 200000

// 任务配置
#define LOW_PRIORITY_TASK_COUNT 3
#define HIGH_PRIORITY_TASK_COUNT 1
#define MONITOR_TASK_COUNT 1

// 优先级
#define MONITOR_PRIORITY 2
#define HIGH_PRIORITY 5
#define LOW_PRIORITY 20

// 栈大小
#define TASK_STACK_SIZE 0x6000 
#define MONITOR_STACK_SIZE 0x6000 

// 任务统计结构
typedef struct {
    UINT32 taskId;
    char name[16];
    UINT32 priority;
    volatile UINT32 scheduleCount;
    volatile UINT64 lastScheduleTime;
    volatile UINT64 totalRunTime;
    volatile UINT64 startTime;
    volatile UINT32 yieldCount;
    volatile UINT32 consecutiveRuns;  // 连续运行计数
    volatile UINT64 lastSwitchTime;   // 上次切换出时间
} TaskStat;

// 全局变量
static TaskStat g_lowTasks[LOW_PRIORITY_TASK_COUNT];
static TaskStat g_highTask;
static TaskStat g_monitorTask;
static volatile BOOL g_testRunning = TRUE;
static volatile UINT32 g_approxSwitchCount = 0;
static volatile UINT32 g_lastRunningTask = 0;
static volatile UINT64 g_lastSwitchTick = 0;

// 原子操作包装（返回递增后的值，按 LOS_AtomicInc 的实际语义调整）
static inline UINT32 AtomicIncrement(volatile UINT32 *value)
{
    LOS_AtomicInc((INT32 *)value);
}

// 低优先级任务 - CPU-bound 模拟 vTPM 实例（不主动 Delay）
static void *LowPriorityTaskEntry(UINTPTR arg)
{
    TaskStat *stat = (TaskStat *)arg;
    if (!stat) return NULL;

    stat->taskId = LOS_CurTaskIDGet();
    stat->startTime = LOS_TickCountGet();

    UINT32 taskIndex = (UINT32)(stat - g_lowTasks); // 通过指针差找到索引

    printf("[LTask%d] Started, ID: 0x%X, Prio: %d\n",
           taskIndex + 1, stat->taskId, LOW_PRIORITY);
    
    UINT64 lastRunTick = 0;

    // 忙循环直到测试结束 (由主函数设置 g_testRunning = FALSE)
    while (g_testRunning) {
        UINT64 currentTick = LOS_TickCountGet();

        // 检查是否是新调度（基于 tick 变化）
        if (currentTick != lastRunTick) {
            stat->scheduleCount++;

            if (stat->lastScheduleTime > 0) {
                UINT64 waitTime = currentTick - stat->lastSwitchTime;
                if (waitTime > 0) {
                    printf("[LTask%d] #%u Wait: %llu ticks\n",
                           taskIndex + 1, stat->scheduleCount, waitTime);
                }
            }

            stat->lastScheduleTime = currentTick;
        }

        // 记录近似切换次数（基于任务ID变化）
        if (g_lastRunningTask != stat->taskId) {
            if (g_lastRunningTask != 0) {
                g_approxSwitchCount++;
            }
            g_lastRunningTask = stat->taskId;
            g_lastSwitchTick = currentTick;
        }

        // CPU-bound 工作：消耗一些 CPU 周期，但不要频繁打印
        volatile UINT64 acc = 0;
        // 调整下面循环次数以匹配目标 CPU 占用（太大可能导致监控信息难以看到）
        for (UINT32 i = 0; i < 100000; i++) {
            acc += i;
        }
        (void)acc; // 避免优化掉

        // 记录运行时间（以 ticks 为单位）
        UINT64 endTick = LOS_TickCountGet();
        if (endTick > currentTick) {
            stat->totalRunTime += (endTick - currentTick);
        }

        // 记录切换出时间
        stat->lastSwitchTime = endTick;

        // 不调用 LOS_TaskDelay — 让任务主动占满 CPU，交由调度器抢占
        lastRunTick = endTick;
    }

    printf("[LTask%d] Completed, Schedules: %u, RunTime: %llu ticks\n",
           taskIndex + 1, stat->scheduleCount, stat->totalRunTime);

    return NULL;
}

// 高优先级任务 - 模拟紧急处理（保持原样）
static void *HighPriorityTaskEntry(UINTPTR arg)
{
    TaskStat *stat = (TaskStat *)arg;
    if (!stat) return NULL;
    
    stat->taskId = LOS_CurTaskIDGet();
    stat->startTime = LOS_TickCountGet();
    
    printf("[HTask] Started, ID: 0x%X, Prio: %d\n",
           stat->taskId, HIGH_PRIORITY);
    
    for (UINT32 i = 0; i < 15 && g_testRunning; i++) {
        UINT64 currentTick = LOS_TickCountGet();
        stat->scheduleCount++;
        
        if (stat->lastScheduleTime > 0) {
            UINT64 waitTime = currentTick - stat->lastSwitchTime;
            printf("[HTask] #%d EMERGENCY, Wait: %llu ticks\n",
                   stat->scheduleCount, waitTime);
        }
        
        stat->lastScheduleTime = currentTick;
        
        // 记录近似切换
        if (g_lastRunningTask != stat->taskId) {
            if (g_lastRunningTask != 0) {
                g_approxSwitchCount++;
            }
            g_lastRunningTask = stat->taskId;
            g_lastSwitchTick = currentTick;
        }
        
        // 模拟紧急任务（短时间计算）
        volatile UINT64 sum = 0;
        for (UINT32 j = 0; j < 1000; j++) {
            sum += j * j * j;
        }
        (void)sum;

        UINT64 endTick = LOS_TickCountGet();
        if (endTick > currentTick) {
            stat->totalRunTime += (endTick - currentTick);
        }
        
        stat->lastSwitchTime = endTick;
        
        // 延迟，保持原有唤醒频率以模拟间歇紧急处理
        LOS_TaskDelay(8);
        stat->yieldCount++;
    }
    
    printf("[HTask] Completed, Schedules: %u, RunTime: %llu ticks\n",
           stat->scheduleCount, stat->totalRunTime);
    
    return NULL;
}

// 监控任务（保持原样，但对“调度分析”文字进行微调）
static void *MonitorTaskEntry(UINTPTR arg)
{
    TaskStat *stat = (TaskStat *)arg;
    if (!stat) return NULL;
    
    stat->taskId = LOS_CurTaskIDGet();
    stat->startTime = LOS_TickCountGet();
    
    printf("[Monitor] Started, ID: 0x%X, Prio: %d\n",
           stat->taskId, MONITOR_PRIORITY);
    
    UINT64 lastReportTime = LOS_TickCountGet();
    UINT32 lastSwitchCount = g_approxSwitchCount;
    
    // 初始记录监控任务
    g_lastRunningTask = stat->taskId;
    g_lastSwitchTick = stat->startTime;
    
    while (g_testRunning) {
        UINT64 currentTime = LOS_TickCountGet();
        
        // 每2秒报告一次
        if ((currentTime - lastReportTime) >= (2 * TICKS_PER_SECOND)) {
            printf("\n====== SYSTEM MONITOR ======\n");
            printf("Time: %llu ticks (%.1f sec)\n",
                   currentTime, (double)currentTime / TICKS_PER_SECOND);
            
            // 时间片配置
            printf("\nTimeslice Config: %d ticks (%d sec)\n",
                   TIMESLICE_TICKS, TIMESLICE_MS / 1000);
            printf("Tick Duration: %d ms\n", 1000 / TICKS_PER_SECOND);
            
            // 近似切换统计
            UINT32 switches = g_approxSwitchCount - lastSwitchCount;
            printf("Approx Task Switches: %u (+%u)\n",
                   g_approxSwitchCount, switches);
            
            // 低优先级任务统计
            printf("\nLow Priority Tasks:\n");
            for (int i = 0; i < LOW_PRIORITY_TASK_COUNT; i++) {
                if (g_lowTasks[i].scheduleCount > 0) {
                    double avgRunTime = (double)g_lowTasks[i].totalRunTime / 
                                       g_lowTasks[i].scheduleCount;
                    printf("  Task%d: %u sched, avg %.1f ticks\n",
                           i + 1, g_lowTasks[i].scheduleCount, avgRunTime);
                }
            }
            
            // 高优先级任务统计
            printf("\nHigh Priority Task:\n");
            if (g_highTask.scheduleCount > 0) {
                double avgRunTime = (double)g_highTask.totalRunTime / 
                                   g_highTask.scheduleCount;
                printf("  Schedules: %u, avg %.1f ticks\n",
                       g_highTask.scheduleCount, avgRunTime);
            }
            
            // 调度分析（说明已改为忙循环测试）
            printf("\nScheduling Analysis:\n");
            printf("  Timeslice: %d ticks (very long by config)\n", TIMESLICE_TICKS);
            printf("  Effective quantum: preemption via tick interrupt / priority\n");
            printf("  Low tasks: CPU-bound (no TaskDelay)\n");
            printf("  High task: intermittent emergency work (TaskDelay(8))\n");
            
            // 计算运行占比（基于 ticks 统计）
            UINT64 totalLowTime = 0;
            for (int i = 0; i < LOW_PRIORITY_TASK_COUNT; i++) {
                totalLowTime += g_lowTasks[i].totalRunTime;
            }
            
            UINT64 reportDuration = currentTime - lastReportTime;
            if (reportDuration > 0) {
                double lowUsage = (double)totalLowTime * 100 / reportDuration;
                double highUsage = (double)g_highTask.totalRunTime * 100 / reportDuration;
                printf("  CPU Usage: Low %.1f%%, High %.1f%%\n", lowUsage, highUsage);
            }
            
            printf("===========================\n\n");
            
            lastReportTime = currentTime;
            lastSwitchCount = g_approxSwitchCount;
        }
        
        // 监控任务自身也需要记录
        if (g_lastRunningTask != stat->taskId) {
            g_approxSwitchCount++;
            g_lastRunningTask = stat->taskId;
            g_lastSwitchTick = currentTime;
        }
        
        LOS_TaskDelay(50);  // 每0.5秒检查一次
    }
    
    return NULL;
}

// 创建测试任务
static UINT32 CreateSchedulerTestTasks(void)
{
    UINT32 ret;
    TSK_INIT_PARAM_S taskParam = {0};
    
    printf("\n=== vTPM Scheduler Test ===\n");
    printf("Config: %d ticks/sec, %d tick timeslice\n",
           TICKS_PER_SECOND, TIMESLICE_TICKS);
    printf("Creating %d low + 1 high + 1 monitor tasks\n\n",
           LOW_PRIORITY_TASK_COUNT);
    
    // 创建低优先级任务（CPU-bound）
    for (int i = 0; i < LOW_PRIORITY_TASK_COUNT; i++) {
        memset_s(&g_lowTasks[i], sizeof(TaskStat), 0, sizeof(TaskStat));
        snprintf_s(g_lowTasks[i].name, sizeof(g_lowTasks[i].name),
                sizeof(g_lowTasks[i].name) - 1, "LowVTPM%d", i + 1);
        g_lowTasks[i].priority = LOW_PRIORITY;

        memset_s(&taskParam, sizeof(taskParam), 0, sizeof(TSK_INIT_PARAM_S));
        taskParam.usTaskPrio = LOW_PRIORITY;
        taskParam.pcName = g_lowTasks[i].name;
        taskParam.uwStackSize = TASK_STACK_SIZE;
        taskParam.pfnTaskEntry = (TSK_ENTRY_FUNC)LowPriorityTaskEntry;
        taskParam.uwArg = (UINTPTR)&g_lowTasks[i];  // 传递指向 TaskStat 的指针

        ret = LOS_TaskCreate(&g_lowTasks[i].taskId, &taskParam);
        if (ret != LOS_OK) {
            printf("Failed to create low task %d: 0x%X\n", i + 1, ret);
            return ret;
        }
    }
    
    // 创建高优先级任务
    memset_s(&g_highTask, sizeof(TaskStat), 0, sizeof(TaskStat));
    strcpy_s(g_highTask.name, sizeof(g_highTask.name), "HighVTPM");
    g_highTask.priority = HIGH_PRIORITY;
    
    memset_s(&taskParam, sizeof(taskParam), 0, sizeof(TSK_INIT_PARAM_S));
    taskParam.usTaskPrio = HIGH_PRIORITY;
    taskParam.pcName = g_highTask.name;
    taskParam.uwStackSize = TASK_STACK_SIZE;
    taskParam.pfnTaskEntry = (TSK_ENTRY_FUNC)HighPriorityTaskEntry;
    taskParam.uwArg = (UINTPTR)&g_highTask;
    
    ret = LOS_TaskCreate(&g_highTask.taskId, &taskParam);
    if (ret != LOS_OK) {
        printf("Failed to create high task: 0x%X\n", ret);
        return ret;
    }
    
    // 创建监控任务
    memset_s(&g_monitorTask, sizeof(TaskStat), 0, sizeof(TaskStat));
    strcpy_s(g_monitorTask.name, sizeof(g_monitorTask.name), "Monitor");
    g_monitorTask.priority = MONITOR_PRIORITY;
    
    memset_s(&taskParam, sizeof(taskParam), 0, sizeof(TSK_INIT_PARAM_S));
    taskParam.usTaskPrio = MONITOR_PRIORITY;
    taskParam.pcName = g_monitorTask.name;
    taskParam.uwStackSize = MONITOR_STACK_SIZE;
    taskParam.pfnTaskEntry = (TSK_ENTRY_FUNC)MonitorTaskEntry;
    taskParam.uwArg = (UINTPTR)&g_monitorTask;
    
    ret = LOS_TaskCreate(&g_monitorTask.taskId, &taskParam);
    if (ret != LOS_OK) {
        printf("Failed to create monitor: 0x%X\n", ret);
        return ret;
    }
    
    printf("All tasks created, test running for 20 seconds...\n");
    return LOS_OK;
}

// 打印最终统计
static void PrintFinalStatistics(void)
{
    printf("\n=== FINAL STATISTICS ===\n");
    
    UINT64 endTime = LOS_TickCountGet();
    double testDuration = (double)endTime / TICKS_PER_SECOND;
    
    printf("Test Duration: %.1f seconds\n", testDuration);
    printf("Approximate Task Switches: %u\n", g_approxSwitchCount);
    
    if (testDuration > 0) {
        printf("Switch Rate: %.1f switches/sec\n",
               (double)g_approxSwitchCount / testDuration);
    }
    
    // 低优先级任务汇总
    printf("\nLow Priority Tasks:\n");
    for (int i = 0; i < LOW_PRIORITY_TASK_COUNT; i++) {
        printf("  Task%d: ", i + 1);
        printf("Schedules: %u, ", g_lowTasks[i].scheduleCount);
        printf("RunTime: %llu ticks, ", g_lowTasks[i].totalRunTime);
        printf("Yields: %u\n", g_lowTasks[i].yieldCount);
    }
    
    // 高优先级任务汇总
    printf("\nHigh Priority Task:\n");
    printf("  Schedules: %u, ", g_highTask.scheduleCount);
    printf("RunTime: %llu ticks, ", g_highTask.totalRunTime);
    printf("Yields: %u\n", g_highTask.yieldCount);
    
    // 调度分析
    printf("\nScheduling Analysis:\n");
    printf("  Configured timeslice: %d ticks\n", TIMESLICE_TICKS);
    printf("  Actual scheduling quantum: preemption via tick interrupt / priority\n");
    printf("  Typical behavior: Low tasks are busy-looping; High task preempts when ready\n");
    
    UINT64 totalRunTime = 0;
    for (int i = 0; i < LOW_PRIORITY_TASK_COUNT; i++) {
        totalRunTime += g_lowTasks[i].totalRunTime;
    }
    totalRunTime += g_highTask.totalRunTime;
    
    if (testDuration > 0) {
        double cpuUsage = (double)totalRunTime * 100 / (testDuration * TICKS_PER_SECOND);
        printf("  Estimated CPU Usage: %.1f%%\n", cpuUsage);
    }
    
    printf("=========================\n");
}

// 主测试函数
UINT32 VtpmSchedulerTest(void)
{
    UINT32 ret;
    
    printf("\nvTPM Multi-Instance Scheduler Test\n");
    printf("Testing LiteOS-M task scheduling with long timeslices\n");
    
    ret = CreateSchedulerTestTasks();
    if (ret != LOS_OK) {
        return ret;
    }
    
    // 运行测试20秒
    LOS_TaskDelay(2000);  // 2000 ticks = 20 seconds
    
    g_testRunning = FALSE;
    LOS_TaskDelay(500);  // 给任务时间结束
    
    PrintFinalStatistics();
    
    printf("\nTest completed\n");
    return LOS_OK;
}

// 应用入口
void app_init(void)
{
    printf("Starting vTPM Scheduler Test...\n");
    VtpmSchedulerTest();
}
