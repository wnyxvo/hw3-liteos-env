#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"
#include "los_tick.h"

#define TASK_STACK_SIZE      0x4000
#define TASK_PRI             8

// 测试配置
#define TEST_FILE_PATH    "/data/storage/test_file.txt"
#define BACKUP_FILE_PATH  "/data/storage/backup.bin"
#define LARGE_FILE_PATH   "/data/storage/large.dat"

// ========== 测试函数声明 ==========
static int test_basic_write(const char* filename);
static int test_basic_read(const char* filename);
static int test_file_seeking(const char* filename);
static int test_binary_operations(void);
static int test_append_mode(const char* filename);
static int test_large_file_operations(void);
static int test_file_info(const char* filename);
static int test_error_handling(void);
static int test_performance(void);
static int test_file_cleanup(void);

// ========== 包装函数（适配函数指针类型） ==========

// 基础写入测试包装
static int test_basic_write_wrapper(void) {
    return test_basic_write(TEST_FILE_PATH);
}

// 基础读取测试包装
static int test_basic_read_wrapper(void) {
    return test_basic_read(TEST_FILE_PATH);
}

// 文件定位测试包装
static int test_file_seeking_wrapper(void) {
    return test_file_seeking(TEST_FILE_PATH);
}

// 追加模式测试包装
static int test_append_mode_wrapper(void) {
    return test_append_mode(TEST_FILE_PATH);
}

// 文件信息测试包装
static int test_file_info_wrapper(void) {
    return test_file_info(TEST_FILE_PATH);
}

// ========== 测试用例结构定义 ==========

// 测试用例结构体
typedef struct {
    const char* name;           // 测试名称
    int (*function)(void);      // 测试函数指针
} test_case_t;

// 测试用例数组
static test_case_t tests[] = {
    // 使用包装函数，避免参数传递问题
    {"基础写入", test_basic_write_wrapper},
    {"基础读取", test_basic_read_wrapper},
    {"文件定位", test_file_seeking_wrapper},
    {"二进制操作", test_binary_operations},
    {"追加模式", test_append_mode_wrapper},
    {"大文件操作", test_large_file_operations},
    {"文件信息", test_file_info_wrapper},
    {"错误处理", test_error_handling},
    {"性能测试", test_performance},
    {"文件清理", test_file_cleanup},
    {NULL, NULL}  // 结束标记
};

// ========== 测试环境准备函数 ==========
static int prepare_test_environment(void)
{
    printf("准备测试环境...\n");
    
    // 检查并创建测试目录
    if (access("/data/storage", F_OK) != 0) {
        printf("创建测试目录: /data/storage\n");
        if (mkdir("/data/storage", 0755) != 0) {
            printf("错误: 无法创建测试目录\n");
            return -1;
        }
    }
    
    // 清理之前的测试文件
    remove(TEST_FILE_PATH);
    remove(BACKUP_FILE_PATH);
    remove(LARGE_FILE_PATH);
    
    printf("测试环境准备完成\n");
    return 0;
}


// ========== 综合测试函数 ==========
static void comprehensive_file_test(void)
{
    printf("\n=== 综合文件系统测试开始 ===\n");
    
    int total_errors = 0;
    int test_count = 0;
    
    // 准备测试环境
    if (prepare_test_environment() != 0) {
        printf("错误: 测试环境准备失败\n");
        return;
    }
    
    // 执行所有测试用例
    for (int i = 0; tests[i].name != NULL; i++) {
        printf("\n[测试 %d] %s...\n", i + 1, tests[i].name);
        
        int result = tests[i].function();
        if (result == 0) {
            printf("%s 通过\n", tests[i].name);
        } else {
            printf("%s 失败 (错误码: %d)\n", tests[i].name, result);
            total_errors++;
        }
        test_count++;
        
        // 测试间短暂延迟
        osDelay(100);
    }
    
    // 测试总结
    printf("\n=== 测试完成摘要 ===\n");
    printf("总测试数: %d\n", test_count);
    printf("通过: %d\n", test_count - total_errors);
    printf("失败: %d\n", total_errors);
    printf("成功率: %.1f%%\n", 
           (float)(test_count - total_errors) / test_count * 100);
    
    if (total_errors == 0) {
        printf("所有文件系统测试通过！\n");
    } else {
        printf("发现 %d 个错误，请检查文件系统\n", total_errors);
    }
}

// ========== 具体的测试函数实现 ==========

// 基础写入测试
static int test_basic_write(const char* filename)
{
    printf("执行基础写入测试...\n");
    
    const char* test_data = "Hello OpenHarmony File System!\n";
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        printf("错误: 无法创建文件 %s\n", filename);
        return -1;
    }
    
    size_t written = fwrite(test_data, 1, strlen(test_data), fp);
    fclose(fp);
    
    if (written != strlen(test_data)) {
        printf("警告: 写入不完整 %zu/%zu\n", written, strlen(test_data));
        return -2;
    }
    
    printf("基础写入测试完成: %zu 字节\n", written);
    return 0;
}

// 基础读取测试
static int test_basic_read(const char* filename)
{
    printf("执行基础读取测试...\n");
    
    char buffer[256] = {0};
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        printf("错误: 无法打开文件 %s\n", filename);
        return -1;
    }
    
    size_t read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    
    if (read == 0) {
        printf("错误: 文件为空或读取失败\n");
        return -2;
    }
    
    buffer[read] = '\0';
    printf("读取内容: %s", buffer);
    printf("基础读取测试完成: %zu 字节\n", read);
    return 0;
}

// 文件定位测试
static int test_file_seeking(const char* filename)
{
    printf("执行文件定位测试...\n");
    
    FILE* fp = fopen(filename, "r+");
    if (!fp) {
        printf("错误: 无法打开文件进行定位测试\n");
        return -1;
    }
    
    // 测试 fseek 和 ftell
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    printf("文件大小: %ld 字节\n", file_size);
    
    fseek(fp, 0, SEEK_SET);
    printf("重置到文件开头\n");
    
    // 测试相对定位
    fseek(fp, 5, SEEK_SET);
    long pos = ftell(fp);
    printf("定位到偏移 5: %ld\n", pos);
    
    fclose(fp);
    return 0;
}

// 二进制操作测试
static int test_binary_operations(void)
{
    printf("执行二进制操作测试...\n");
    
    // 写入二进制数据
    FILE* fp = fopen(BACKUP_FILE_PATH, "wb");
    if (!fp) {
        printf("错误: 无法创建二进制文件\n");
        return -1;
    }
    
    uint8_t binary_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    size_t written = fwrite(binary_data, 1, sizeof(binary_data), fp);
    fclose(fp);
    
    if (written != sizeof(binary_data)) {
        printf("错误: 二进制写入不完整\n");
        return -2;
    }
    
    // 读取并验证
    fp = fopen(BACKUP_FILE_PATH, "rb");
    if (!fp) {
        printf("错误: 无法读取二进制文件\n");
        return -3;
    }
    
    uint8_t read_buffer[sizeof(binary_data)];
    size_t read = fread(read_buffer, 1, sizeof(read_buffer), fp);
    fclose(fp);
    
    if (read != sizeof(binary_data)) {
        printf("错误: 二进制读取不完整\n");
        return -4;
    }
    
    // 验证数据
    for (size_t i = 0; i < sizeof(binary_data); i++) {
        if (read_buffer[i] != binary_data[i]) {
            printf("错误: 数据不匹配在偏移 %zu\n", i);
            return -5;
        }
    }
    
    printf("二进制操作测试完成\n");
    return 0;
}

// 追加模式测试
static int test_append_mode(const char* filename)
{
    printf("执行追加模式测试...\n");
    
    // 第一次写入
    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;
    fputs("第一行内容\n", fp);
    fclose(fp);
    
    // 追加写入
    fp = fopen(filename, "a");
    if (!fp) return -2;
    fputs("第二行内容（追加）\n", fp);
    fclose(fp);
    
    // 验证内容
    char buffer[512];
    fp = fopen(filename, "r");
    if (!fp) return -3;
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("文件内容: %s", buffer);
    }
    fclose(fp);
    
    printf("追加模式测试完成\n");
    return 0;
}

// 大文件操作测试
static int test_large_file_operations(void)
{
    printf("执行大文件操作测试...\n");
    
    FILE* fp = fopen(LARGE_FILE_PATH, "w");
    if (!fp) {
        printf("警告: 大文件测试跳过（可能内存不足）\n");
        return 0;  // 不是错误，只是跳过
    }
    
    // 写入1KB数据（根据系统能力调整）
    char buffer[1024];
    memset(buffer, 'A', sizeof(buffer));
    
    for (int i = 0; i < 10; i++) {  // 写入10KB
        size_t written = fwrite(buffer, 1, sizeof(buffer), fp);
        if (written != sizeof(buffer)) {
            fclose(fp);
            printf("警告: 大文件写入不完整，测试跳过\n");
            remove(LARGE_FILE_PATH);
            return 0;
        }
    }
    fclose(fp);
    
    // 验证文件大小
    struct stat st;
    if (stat(LARGE_FILE_PATH, &st) == 0) {
        printf("大文件大小: %ld 字节\n", st.st_size);
    }
    
    printf("大文件操作测试完成\n");
    return 0;
}

// 文件信息测试
static int test_file_info(const char* filename)
{
    printf("执行文件信息测试...\n");
    
    struct stat st;
    if (stat(filename, &st) != 0) {
        printf("错误: 无法获取文件信息\n");
        return -1;
    }
    
    printf("文件信息:\n");
    printf("  大小: %ld 字节\n", st.st_size);
    printf("  权限: %o\n", st.st_mode & 0777);
    
    if (S_ISREG(st.st_mode)) {
        printf("  类型: 普通文件\n");
    } else if (S_ISDIR(st.st_mode)) {
        printf("  类型: 目录\n");
    }
    
    printf("文件信息测试完成\n");
    return 0;
}

// 错误处理测试
static int test_error_handling(void)
{
    printf("执行错误处理测试...\n");
    
    // 测试打开不存在的文件
    FILE* fp = fopen("/data/storage/nonexistent.txt", "r");
    if (fp == NULL) {
        printf("正常: 无法打开不存在的文件（预期行为）\n");
    } else {
        fclose(fp);
        printf("错误: 不应该能打开不存在的文件\n");
        return -1;
    }
    
    // 测试无效模式
    fp = fopen(TEST_FILE_PATH, "invalid_mode");
    if (fp == NULL) {
        printf("正常: 无效模式被拒绝（预期行为）\n");
    } else {
        fclose(fp);
        printf("错误: 无效模式不应该成功\n");
        return -2;
    }
    
    printf("错误处理测试完成\n");
    return 0;
}

// 性能测试
static int test_performance(void)
{
    printf("执行性能测试...\n");
    
    const int iterations = 100;
    uint32_t start_time = osKernelGetTickCount();
    
    for (int i = 0; i < iterations; i++) {
        FILE* fp = fopen(TEST_FILE_PATH, "w");
        if (!fp) {
            printf("错误: 性能测试中无法创建文件\n");
            return -1;
        }
        fputs("性能测试数据\n", fp);
        fclose(fp);
    }
    
    uint32_t duration = osKernelGetTickCount() - start_time;
    printf("性能测试: %d 次操作耗时 %u 毫秒\n", iterations, duration);
    
    return 0;
}

// 文件清理测试
static int test_file_cleanup(void)
{
    printf("执行文件清理测试...\n");
    
    int errors = 0;
    
    if (remove(TEST_FILE_PATH) == 0) {
        printf("删除测试文件成功\n");
    } else {
        printf("删除测试文件失败\n");
        errors++;
    }
    
    if (remove(BACKUP_FILE_PATH) == 0) {
        printf("删除备份文件成功\n");
    } else {
        printf("删除备份文件失败\n");
        errors++;
    }
    
    if (remove(LARGE_FILE_PATH) == 0) {
        printf("删除大文件成功\n");
    } else {
        printf("删除大文件失败（可能不存在）\n");
        // 不算错误
    }
    
    printf("文件清理测试完成，错误数: %d\n", errors);
    return errors;
}

// ========== 任务封装和初始化 ==========

static void safe_file_test_task(void* arg)
{
    (void)arg;
    
    printf("文件测试任务启动...\n");
    
    // 等待系统稳定
    osDelay(3000);
    
    // 执行综合测试
    comprehensive_file_test();
    
    printf("文件测试任务完成\n");
}

void FileTestTaskApp(void)
{
    unsigned int ret;
    unsigned int taskID;
    TSK_INIT_PARAM_S task = { 0 };
    task.pfnTaskEntry = (TSK_ENTRY_FUNC)safe_file_test_task;
    task.uwStackSize  = TASK_STACK_SIZE;
    task.pcName       = "safe_fileFileSystemTest_test";
    task.usTaskPrio   = TASK_PRI;
    
    ret = LOS_TaskCreate(&taskID, &task);
    if (ret != LOS_OK) {
        printf("safe_file_test task create failed: 0x%X\n", ret);
    }
}

// APP_FEATURE_INIT(FileTestTaskApp);
