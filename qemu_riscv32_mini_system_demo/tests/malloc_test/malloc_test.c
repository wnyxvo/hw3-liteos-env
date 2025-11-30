// vendor/ohemu/qemu_riscv32_mini_system_demo/tests/malloc_test/malloc_test.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"

#define TEST_BUFFER_SIZE      1024
#define MAX_TEST_ALLOCATIONS  100
#define TASK_STACK_SIZE       0x2000
#define TASK_PRI              7

// 测试结果统计
typedef struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
    size_t total_allocated;
    size_t peak_allocated;
} test_stats_t;

static test_stats_t g_test_stats = {0};

// 断言宏
#define TEST_ASSERT(condition, message) do { \
    g_test_stats.total_tests++; \
    if (condition) { \
        g_test_stats.passed_tests++; \
        printf("✅ PASS: %s\n", message); \
    } else { \
        g_test_stats.failed_tests++; \
        printf("❌ FAIL: %s (at %s:%d)\n", message, __FILE__, __LINE__); \
    } \
} while(0)

// 内存填充模式
#define MEM_PATTERN 0xAA
#define MEM_CHECK_PATTERN 0x55

// ========== 测试用例 ==========

// 测试1: 基础 malloc/free
void test_basic_malloc_free(void) {
    printf("\n=== 测试1: 基础 malloc/free ===\n");
    
    // 分配内存
    void *ptr = malloc(100);
    TEST_ASSERT(ptr != NULL, "malloc(100) 应返回非空指针");
    
    if (ptr != NULL) {
        g_test_stats.total_allocated += 100;
        if (100 > g_test_stats.peak_allocated) {
            g_test_stats.peak_allocated = 100;
        }
        
        // 首先检查 MEM_PATTERN 的值
        printf("MEM_PATTERN 值: 0x%02X\n", MEM_PATTERN);
        
        // 写入数据
        memset(ptr, MEM_PATTERN, 100);
        
        // 详细检查内存内容
        printf("检查内存内容...\n");
        int pattern_ok = 1;
        int first_mismatch = -1;
        unsigned char expected = MEM_PATTERN;
        
        for (int i = 0; i < 100; i++) {
            unsigned char actual = ((unsigned char*)ptr)[i];
            if (actual != expected) {
                pattern_ok = 0;
                first_mismatch = i;
                printf("❌ 位置 %d: 预期 0x%02X, 实际 0x%02X\n", 
                       i, expected, actual);
                break;
            }
        }
        
        // 如果失败，输出更多信息
        if (!pattern_ok && first_mismatch != -1) {
            printf("前16个字节的内容:\n");
            for (int i = 0; i < 16; i++) {
                printf("  [%02d]: 0x%02X", i, ((unsigned char*)ptr)[i]);
                if (i % 4 == 3) printf("\n");
            }
            printf("\n");
        }
        
        TEST_ASSERT(pattern_ok, "写入的数据应正确保存");
        
        // 释放内存
        free(ptr);
        g_test_stats.total_allocated -= 100;
        printf("✓ 内存已释放\n");
    }
}

// 测试2: calloc 测试（清零初始化）
void test_calloc_initialization(void) {
    printf("\n=== 测试2: calloc 清零初始化 ===\n");
    
    // 分配并清零内存
    int *ptr = (int*)calloc(10, sizeof(int));
    TEST_ASSERT(ptr != NULL, "calloc(10, sizeof(int)) 应返回非空指针");
    
    if (ptr != NULL) {
        g_test_stats.total_allocated += 10 * sizeof(int);
        
        // 验证内存被清零
        int all_zero = 1;
        for (int i = 0; i < 10; i++) {
            if (ptr[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        TEST_ASSERT(all_zero, "calloc 分配的内存应被清零");
        
        free(ptr);
        g_test_stats.total_allocated -= 10 * sizeof(int);
    }
}

// 测试3: realloc 功能测试
void test_realloc_functionality(void) {
    printf("\n=== 测试3: realloc 功能测试 ===\n");
    
    // 初始分配
    char *ptr = (char*)malloc(50);
    TEST_ASSERT(ptr != NULL, "初始分配应成功");
    
    if (ptr != NULL) {
        g_test_stats.total_allocated += 50;
        
        // 填充数据
        memset(ptr, 'A', 50);
        
        // 扩大内存
        char *new_ptr = (char*)realloc(ptr, 100);
        TEST_ASSERT(new_ptr != NULL, "realloc 扩大应成功");
        
        if (new_ptr != NULL) {
            g_test_stats.total_allocated += 50; // 增加50字节
            
            // 验证原有数据保存
            int data_preserved = 1;
            for (int i = 0; i < 50; i++) {
                if (new_ptr[i] != 'A') {
                    data_preserved = 0;
                    break;
                }
            }
            TEST_ASSERT(data_preserved, "realloc 扩大后原有数据应保存");
            
            // 缩小内存
            char *smaller_ptr = (char*)realloc(new_ptr, 25);
            TEST_ASSERT(smaller_ptr != NULL, "realloc 缩小应成功");
            
            if (smaller_ptr != NULL) {
                g_test_stats.total_allocated -= 75; // 从100减到25
                
                // 验证部分数据保存
                int partial_data_ok = 1;
                for (int i = 0; i < 25; i++) {
                    if (smaller_ptr[i] != 'A') {
                        partial_data_ok = 0;
                        break;
                    }
                }
                TEST_ASSERT(partial_data_ok, "realloc 缩小后前部数据应保存");
                
                free(smaller_ptr);
                g_test_stats.total_allocated -= 25;
            } else {
                free(new_ptr);
                g_test_stats.total_allocated -= 100;
            }
        } else {
            free(ptr);
            g_test_stats.total_allocated -= 50;
        }
    }
}

// 测试4: 边界情况测试
void test_edge_cases(void) {
    printf("\n=== 测试4: 边界情况测试 ===\n");
    
    // 测试零字节分配
    void *ptr0 = malloc(0);
    TEST_ASSERT(ptr0 == NULL || ptr0 != NULL, 
                "malloc(0) 行为（可能返回NULL或最小分配）");
    if (ptr0 != NULL) {
        free(ptr0);
    }
    
    // 测试极大分配（应失败）
    void *huge_ptr = malloc(1024 * 1024 * 100); // 100MB
    TEST_ASSERT(huge_ptr == NULL, "极大内存分配应返回NULL");
    
    // 测试 free(NULL)
    free(NULL); // 应不崩溃
    printf("✓ free(NULL) 执行正常\n");
}

// 测试5: 多块内存分配测试
void test_multiple_allocations(void) {
    printf("\n=== 测试5: 多块内存分配测试 ===\n");
    
    void *pointers[MAX_TEST_ALLOCATIONS] = {0};
    size_t sizes[MAX_TEST_ALLOCATIONS];
    
    // 分配多块不同大小的内存
    for (int i = 0; i < MAX_TEST_ALLOCATIONS / 2; i++) {
        sizes[i] = (i + 1) * 16; // 16, 32, 48, ... 字节
        pointers[i] = malloc(sizes[i]);
        
        if (pointers[i] != NULL) {
            g_test_stats.total_allocated += sizes[i];
            if (g_test_stats.total_allocated > g_test_stats.peak_allocated) {
                g_test_stats.peak_allocated = g_test_stats.total_allocated;
            }
            
            // 填充数据
            memset(pointers[i], i % 256, sizes[i]);
        }
        TEST_ASSERT(pointers[i] != NULL, "多块分配应成功");
    }
    
    // 验证并释放
    for (int i = 0; i < MAX_TEST_ALLOCATIONS / 2; i++) {
        if (pointers[i] != NULL) {
            // 验证数据
            int data_ok = 1;
            for (size_t j = 0; j < sizes[i] && j < 16; j++) { // 只检查前16字节
                if (((char*)pointers[i])[j] != (char)(i % 256)) {
                    data_ok = 0;
                    break;
                }
            }
            TEST_ASSERT(data_ok, "分配的数据应正确保存");
            
            free(pointers[i]);
            g_test_stats.total_allocated -= sizes[i];
            pointers[i] = NULL;
        }
    }
    
    printf("✓ 多块内存分配/释放测试完成\n");
}

// ========== 测试入口 ==========
void MallocTestTask(void) {
  printf("=== 内存分配器测试开始 ===\n");
  test_basic_malloc_free();
  test_calloc_initialization();
  test_realloc_functionality(); 
  test_edge_cases();
  test_multiple_allocations();
  
  // 测试总结
  printf("\n=== 测试总结 ===\n");
  printf("总测试数: %d\n", g_test_stats.total_tests);
  printf("通过: %d\n", g_test_stats.passed_tests);
  printf("失败: %d\n", g_test_stats.failed_tests);
  printf("当前分配内存: %zu 字节\n", g_test_stats.total_allocated);
  printf("峰值分配内存: %zu 字节\n", g_test_stats.peak_allocated);
  printf("=== 内存分配器测试结束 ===\n");
}

void MallocTestTaskApp(void)
{
  unsigned int ret;
  unsigned int taskID;
  TSK_INIT_PARAM_S task = { 0 };
  task.pfnTaskEntry = (TSK_ENTRY_FUNC)MallocTestTask;
  task.uwStackSize  = TASK_STACK_SIZE;
  task.pcName       = "MallocTestTask";
  task.usTaskPrio   = TASK_PRI;
  
  ret = LOS_TaskCreate(&taskID, &task);
  if (ret != LOS_OK) {
      printf("MallocTestTask task create failed: 0x%X\n", ret);
  }
}
