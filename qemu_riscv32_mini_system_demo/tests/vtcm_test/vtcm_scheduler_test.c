#include "los_task.h"
#include "los_memory.h"
#include "los_tick.h"
#include "los_atomic.h"
#include "securec.h"
#include "stdio.h"

/* ================= 配置区域 ================= */
// 测试总时长 (秒)
#define TEST_DURATION_SEC       20

// 栈大小 (根据实际内存调整)
#define TASK_STACK_SIZE         0x1000

// 优先级配置 (0最高, 31最低)
#define PRIO_MONITOR            3   // 监控任务
#define PRIO_HIGH_URGENT        5   // 抢占任务 (模拟中断/紧急业务)
#define PRIO_LOW_WORKER         10  // 普通工作任务 (模拟 vTPM 计算)

// 可视化 Trace 缓冲区长度
#define TRACE_BUF_LEN           64

/* ================= 数据结构 ================= */
typedef enum {
    TASK_TYPE_CPU_HOG = 0, // 死循环霸占 CPU
    TASK_TYPE_YIELDER,     // 主动礼让 (Yield)
    TASK_TYPE_PREEMPTOR    // 高优先级抢占
} TaskType;

typedef struct {
    UINT32 taskId;
    char name[16];
    TaskType type;
    UINT64 totalRunTicks;     // 总运行时间
    UINT64 lastStartTime;     // 最近一次切入时间
    UINT32 contextSwitchCount;// 切入次数
} TaskStat;

/* ================= 全局变量 ================= */
static TaskStat g_lowStats[3]; // 3个低优先级任务
static TaskStat g_highStat;    // 1个高优先级任务
static BOOL g_testRunning = TRUE;

// Trace 缓冲区 (用于可视化调度序列)
static char g_traceBuf[TRACE_BUF_LEN + 1];
static UINT32 g_traceIdx = 0;

// 上一次运行的任务ID (用于检测切换)
static UINT32 g_lastRunningTaskId = 0xFFFFFFFF;

/* ================= 辅助函数 ================= */

/**
 * @brief 安全地向 Trace 缓冲区写入一个字符
 * 使用关中断保护，防止多核或中断打断导致 Buffer 错乱
 */
static void AddToTrace(char c)
{
    UINT32 intSave = LOS_IntLock();
    if (g_traceIdx < TRACE_BUF_LEN) {
        g_traceBuf[g_traceIdx++] = c;
    }
    LOS_IntRestore(intSave);
}

/**
 * @brief 模拟 CPU 负载
 * @param intensity 循环次数
 */
static void BurnCpu(UINT32 intensity)
{
    volatile UINT32 res = 0;
    for (UINT32 i = 0; i < intensity; i++) {
        res += i * i;
    }
    (void)res;
}

/* ================= 任务入口 ================= */

/**
 * @brief 低优先级工作任务入口
 * Task 0 & 1: 死循环 (测试时间片轮转)
 * Task 2: 计算后 Yield (测试主动放弃)
 */
static void *WorkerTaskEntry(UINTPTR arg)
{
    UINT32 idx = (UINT32)arg;
    TaskStat *stat = &g_lowStats[idx];
    stat->taskId = LOS_CurTaskIDGet();
    char traceChar = 'A' + idx; // Task0='A', Task1='B', Task2='C'

    printf("[%s] Started. ID: 0x%x, Type: %s\n", 
           stat->name, stat->taskId, 
           stat->type == TASK_TYPE_YIELDER ? "Yield" : "Hog");

    while (g_testRunning) {
        // --- 1. 统计与 Trace 逻辑 ---
        UINT32 currId = LOS_CurTaskIDGet();
        if (g_lastRunningTaskId != currId) {
            // 发生了一次切换，切到了我
            g_lastRunningTaskId = currId;
            stat->contextSwitchCount++;
            stat->lastStartTime = LOS_TickCountGet();
            AddToTrace(traceChar);
        }

        // --- 2. 模拟业务负载 ---
        // 每次跑一小段，模拟计算过程
        BurnCpu(1000); 

        // --- 3. 更新运行时间 (非精确，仅作参考) ---
        UINT64 now = LOS_TickCountGet();
        if (now > stat->lastStartTime) {
            stat->totalRunTicks += (now - stat->lastStartTime);
            stat->lastStartTime = now;
        }

        // --- 4. 行为分支 ---
        if (stat->type == TASK_TYPE_YIELDER) {
            // 这里的 Yield 会导致该任务放弃剩余时间片，重新排队
            // 预期结果：在 Log 中，字符 'C' 出现的频率高，但连续长度短
            LOS_TaskYield();
        }
    }
    return NULL;
}

/**
 * @brief 高优先级抢占任务入口
 * 周期性醒来，执行极短时间，验证“抢占恢复”逻辑
 */
static void *PreemptorTaskEntry(UINTPTR arg)
{
    g_highStat.taskId = LOS_CurTaskIDGet();
    printf("[%s] Started. ID: 0x%x (High Prio)\n", g_highStat.name, g_highStat.taskId);

    while (g_testRunning) {
        // 记录切入
        if (g_lastRunningTaskId != g_highStat.taskId) {
            g_lastRunningTaskId = g_highStat.taskId;
            g_highStat.contextSwitchCount++;
            AddToTrace('!'); // '!' 代表高优先级抢占
        }

        // 极短的爆发计算 (模拟中断处理或紧急任务)
        // 注意：这里没有 Yield，也没有长时间 Delay，靠执行完逻辑后主动休眠
        BurnCpu(1000); 

        // 休眠 1 秒 (1000ms / Tick周期)
        // 使用 LOSCFG_BASE_CORE_TICK_PER_SECOND 宏确保跨平台兼容
        LOS_TaskDelay(LOSCFG_BASE_CORE_TICK_PER_SECOND); 
    }
    return NULL;
}

/**
 * @brief 监控任务
 * 负责打印统计信息和清空 Trace Buffer
 */
static void *MonitorTaskEntry(UINTPTR arg)
{
    printf("[Monitor] Started.\n");
    UINT32 printInterval = 2 * LOSCFG_BASE_CORE_TICK_PER_SECOND; // 每2秒打印一次
    
    while (g_testRunning) {
        LOS_TaskDelay(printInterval);

        printf("\n=== Scheduler Snapshot (Time: %llu ticks) ===\n", LOS_TickCountGet());
        
        // 1. 打印 Trace 流 (原子读取并清空)
        UINT32 intSave = LOS_IntLock();
        g_traceBuf[TRACE_BUF_LEN] = '\0'; // 确保字符串结束符
        printf("Flow: [%s]\n", g_traceBuf);
        // 清空 Buffer
        memset_s(g_traceBuf, sizeof(g_traceBuf), 0, sizeof(g_traceBuf));
        g_traceIdx = 0;
        LOS_IntRestore(intSave);

        // 2. 打印表格
        printf("%-10s | %-6s | %-8s | %-10s\n", "Name", "Type", "Switches", "RunTicks");
        printf("-----------|--------|----------|----------\n");
        
        for (int i = 0; i < 3; i++) {
            printf("%-10s | %-6s | %-8u | %-10llu\n", 
                   g_lowStats[i].name,
                   g_lowStats[i].type == TASK_TYPE_YIELDER ? "Yield" : "Hog",
                   g_lowStats[i].contextSwitchCount,
                   g_lowStats[i].totalRunTicks);
        }
        printf("%-10s | %-6s | %-8u | -\n", 
               g_highStat.name, "High", g_highStat.contextSwitchCount);
        
        printf("==========================================\n");
    }
    return NULL;
}

/* ================= 初始化函数 ================= */

UINT32 SchedulerTestStart(void)
{
    UINT32 ret;
    TSK_INIT_PARAM_S taskParam = {0};

    printf("\n>>> LiteOS-M Scheduler Optimization Test <<<\n");

    // 1. 初始化统计结构并创建 Worker 任务
    for (int i = 0; i < 3; i++) {
        memset_s(&g_lowStats[i], sizeof(TaskStat), 0, sizeof(TaskStat));
        sprintf_s(g_lowStats[i].name, sizeof(g_lowStats[i].name), "Worker%d", i);
        
        // Task 0, 1 是霸占型，Task 2 是礼让型
        g_lowStats[i].type = (i == 2) ? TASK_TYPE_YIELDER : TASK_TYPE_CPU_HOG;

        memset_s(&taskParam, sizeof(TSK_INIT_PARAM_S), 0, sizeof(TSK_INIT_PARAM_S));
        taskParam.pfnTaskEntry = (TSK_ENTRY_FUNC)WorkerTaskEntry;
        taskParam.uwStackSize  = TASK_STACK_SIZE;
        taskParam.pcName       = g_lowStats[i].name;
        taskParam.usTaskPrio   = PRIO_LOW_WORKER; // 所有 Worker 优先级相同
        taskParam.uwArg        = (UINTPTR)i;

        ret = LOS_TaskCreate(&g_lowStats[i].taskId, &taskParam);
        if (ret != LOS_OK) {
            printf("Error: Create Worker%d failed: 0x%x\n", i, ret);
            return ret;
        }
    }

    // 2. 创建高优先级抢占任务
    memset_s(&g_highStat, sizeof(TaskStat), 0, sizeof(TaskStat));
    sprintf_s(g_highStat.name, sizeof(g_highStat.name), "UrgentTask");
    g_highStat.type = TASK_TYPE_PREEMPTOR;

    taskParam.pfnTaskEntry = (TSK_ENTRY_FUNC)PreemptorTaskEntry;
    taskParam.uwStackSize  = TASK_STACK_SIZE;
    taskParam.pcName       = g_highStat.name;
    taskParam.usTaskPrio   = PRIO_HIGH_URGENT; // 优先级更高
    taskParam.uwArg        = 0;

    ret = LOS_TaskCreate(&g_highStat.taskId, &taskParam);
    if (ret != LOS_OK) return ret;

    // 3. 创建监控任务
    taskParam.pfnTaskEntry = (TSK_ENTRY_FUNC)MonitorTaskEntry;
    taskParam.pcName       = "Monitor";
    taskParam.usTaskPrio   = PRIO_MONITOR; // 优先级最高(或次高)，保证打印不被阻塞

    UINT32 monitorId;
    ret = LOS_TaskCreate(&monitorId, &taskParam);
    if (ret != LOS_OK) return ret;

    // 4. 主线程延时，等待测试结束
    LOS_TaskDelay(TEST_DURATION_SEC * LOSCFG_BASE_CORE_TICK_PER_SECOND);
    
    // 5. 结束测试
    g_testRunning = FALSE;
    printf("\n>>> Test Finished <<<\n");

    return LOS_OK;
}

// 应用入口
void app_init(void)
{
    printf("Starting vTPM Scheduler Test...\n");
    SchedulerTestStart();
}