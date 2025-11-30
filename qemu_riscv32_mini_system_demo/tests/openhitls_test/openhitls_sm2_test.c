#include "ohos_init.h"
#include "ohos_types.h"
#include <stdio.h>
#include <unistd.h>

#include "cmsis_os2.h"

#include "los_task.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"
#include "bsl_params.h"
#include "crypt_util_rand.h"

#define HITLS_CRYPTO_SM2
#define HITLS_CRYPTO_SM2_CRYPT

#include "crypt_sm2.h"  
#include "crypt_sm2.h"  
#include "crypt_local_types.h"
#include "crypt_util_rand.h"
// #include "crypt_eal_rand.h"

#define TASK_STACK_SIZE (1024*20) 
#define TASK_PRIO       25
#define UINT8_MAX_NUM   255


typedef int32_t (*myfun)(uint8_t *myrandNum, uint32_t myLen);
typedef int32_t (*Testfun)(uint8_t *rand, uint32_t randLen);
static myfun myfuntest=NULL;
Testfun testfun1 = NULL;

int32_t Myfun(uint8_t *myrandNum, uint32_t myLen)
{
    printf("myfun = %d\n", myLen);
    for (uint32_t i = 0; i < myLen; i++) {
        myrandNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
    return 0;
    return 0;
}


int32_t TestRandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }
    return 0;
}

/* =====================  任务入口  =======  ============== */

static void HitlsSM2TestTask(void)
{
    CRYPT_SM2_Ctx *ctx;
    uint32_t outlen;
    uint8_t out[256];
    uint8_t message[] = "encryption standard NEWPLAN!!";
    int32_t ret;

    ctx = CRYPT_SM2_NewCtx();
    if(ctx == NULL)
    {
        printf("CRYPT_SM2_NewCtx fail!\n");
        return ; // 本质来说不能返回，应该循环执行或者杀死任务
    }
    printf("CRYPT_SM2_NewCtx successsa!\n");
    CRYPT_RandRegist(TestRandFunc);
    ret = CRYPT_SM2_Gen(ctx);
    if(ret != CRYPT_SUCCESS)
    {
        if(ret == CRYPT_MEM_ALLOC_FAIL)
        {
            printf("CRYPT_MEM_ALLOC_FAIL fail!\n");
        }else if(ret == CRYPT_NULL_INPUT)
        {
            printf("CRYPT_NULL_INPUT fail!\n");
        }else{
            // error
            printf("other fail! ret = %d\n", ret);
        }
        return ;
    }
    printf("CRYPT_SM2_Gen successsa!\n");

    outlen = 256;  // 实际输出 
    ret = CRYPT_SM2_Encrypt(ctx, message, strlen(message), out, &outlen);
    if(ret != CRYPT_SUCCESS)
    {
        printf("CRYPT_SM2_Encrypt fail!\n");
        if(ret == CRYPT_NULL_INPUT)
        {
            printf("CRYPT_SM2_Encrypt CRYPT_NULL_INPUT fail!\n");
        }else{
            // error
            printf("CRYPT_SM2_Encrypt other fail! ret = %d\n", ret);
        }
        return 0;
    }
    printf("CRYPT_SM2_Encrypt successsa!\n");
    printf("outlen = %d\n", outlen);

    int a=5;
    while(a--)
    {
        for(int i=0; i<outlen;i++)
        {
            printf("%02x", out[i]);
        }
        printf("\n");
        sleep(1);
    }

    int len = strlen(message);
    ret = CRYPT_SM2_Decrypt(ctx, out, outlen, message, &len);
    if(ret != CRYPT_SUCCESS)
    {
        printf("CRYPT_SM2_Decrypt fail!\n");
        if(ret == CRYPT_NULL_INPUT)
        {
            printf("CRYPT_SM2_Decrypt CRYPT_NULL_INPUT fail!\n");
        }else{
            // error  CRYPT_SM2_ERR_EMPTY_KEY 
            printf("CRYPT_SM2_Decrypt other fail! ret = %d\n", ret);
        }
        return 0;
    }
    printf("CRYPT_SM2_Decrypt successsa!\n");
    printf("len = %d\n", len);
    a=5;
    while(a--)
    {
        printf("%s", message);
        printf("\n");
        sleep(1);
    }
    CRYPT_SM2_FreeCtx(ctx);
}


void HitlsSM2TestTaskApp(void)
{
    unsigned int taskID;
    TSK_INIT_PARAM_S task = { 0 };

    task.pfnTaskEntry = (TSK_ENTRY_FUNC)HitlsSM2TestTask;
    task.uwStackSize  = TASK_STACK_SIZE;
    task.pcName       = "hitls_sm2_test";
    task.usTaskPrio   = TASK_PRIO;

    unsigned int ret = LOS_TaskCreate(&taskID, &task);
    if (ret != LOS_OK)
        printf("hitls_sm2_test task create failed: 0x%X\n", ret);
}
