#include <stdio.h>
#include <string.h>
#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"

#define TASK_STACK_SIZE      0x1000
#define TASK_PRI             8

void safe_file_test(void *arg)
{
    (void)arg;
    osDelay(3000);  // 等待文件系统就绪
    
    // 您的文件测试代码
    const char *path = "/data/storage/test.txt";
    const char *str = "Hello RISC-V from OpenHarmony!\n";
    
    FILE *fp = fopen(path, "w+");
    if (fp) {
        fwrite(str, 1, strlen(str), fp);
        fclose(fp);
        printf("文件测试成功\n");
    } else {
        printf("文件测试失败\n");
    }
}

void FileTestThreadApp(void)
{
    osThreadAttr_t attr;
    attr.name = "FileTestThreadApp";
    attr.attr_bits = 0U;
    attr.cb_mem = NULL;
    attr.cb_size = 0U;
    attr.stack_mem = NULL;
    attr.stack_size = 1024;
    attr.priority = TASK_PRI;
    if (osThreadNew((osThreadFunc_t)safe_file_test, NULL, &attr) == NULL) {
        printf("文件测试任务创建失败\n");
    }
}

void FileTestTaskApp(void)
{
    unsigned int ret;
    unsigned int taskID;
    TSK_INIT_PARAM_S task = { 0 };
    task.pfnTaskEntry = (TSK_ENTRY_FUNC)safe_file_test;
    task.uwStackSize  = TASK_STACK_SIZE;
    task.pcName       = "safe_file_test";
    task.usTaskPrio   = TASK_PRI;
    
    ret = LOS_TaskCreate(&taskID, &task);
    if (ret != LOS_OK) {
        printf("safe_file_test task create failed: 0x%X\n", ret);
    }
}

// APP_FEATURE_INIT(init_file_test);
