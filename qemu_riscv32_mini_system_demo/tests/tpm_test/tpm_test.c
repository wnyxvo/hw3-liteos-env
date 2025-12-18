/*
 * TPM 2.0 Modular Test Suite
 * Protocol: Big-Endian (Network Byte Order) required for all TPM commands.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h> // for isspace, isxdigit

#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"

// Task Configuration
#define TASK_STACK_SIZE      0x4000 
#define TASK_PRI             16

// TPM Constants
#define TPM_ST_NO_SESSIONS       0x8001
#define TPM_ST_SESSIONS          0x8002

#define TPM_CC_Startup           0x00000144
#define TPM_CC_SelfTest          0x00000143
#define TPM_CC_GetRandom         0x0000017B
#define TPM_CC_PCR_Read          0x0000017E
#define TPM_CC_GetCapability     0x0000017A
#define TPM_CC_Hash              0x0000017D
#define TPM_CC_NV_DefineSpace    0x0000012A
#define TPM_CC_NV_Write          0x00000137
#define TPM_CC_NV_Read           0x0000014E
#define TPM_CC_CreatePrimary     0x00000131
#define TPM_CC_Create            0x00000153
#define TPM_CC_Load              0x00000157
#define TPM_CC_Sign              0x0000015D
#define TPM_CC_RSA_Decrypt       0x0000015B
#define TPM_CC_FlushContext      0x00000165

#define TPM_SU_CLEAR             0x0000
#define TPM_SU_STATE             0x0001

#define TPM_CAP_ALGS             0x00000000
#define TPM_CAP_TPM_PROPERTIES   0x00000006
#define TPM_PT_FIXED             0x00000100

#define TPM_RC_SUCCESS           0x00000000
#define TPM_RC_INITIALIZE        0x00000100
#define TPM_RC_FAILURE           0x00000101

#define TPM_RC_NV_DEFINED        0x0000014B

#define TPM_RS_PW                0x40000009

#define TPM_ALG_RSA              0x0001
#define TPM_ALG_AES              0x0006

#define TPM_ALG_SHA256           0x000B
#define TPM_ALG_NULL             0x0010
#define TPM_ALG_SM2              0x001B
#define TPM_ALG_SM3_256          0x0012
#define TPM_ALG_SM4              0x0013
#define TPM_ALG_RSASSA           0x0014
#define TPM_ALG_ECC              0x0023
#define TPM_ALG_CFB              0x0043

#define TPM_ALG_AES_128_CFB      0x0043  /* note: mode encoding may vary; here for human clarity */
#define TPM_ALG_KDF1_SP800_56A   0x0020  /* common KDF; alternative: 0x0022 KDF_CTR_HMAC_SHA256 */
#define TPM_ALG_KDF_CTR          0x0022  /* KDF for SM2 (Usually KDF_CTR_HMAC_SM3) */

#ifndef TPM_ECC_SM2_P256
#define TPM_ECC_SM2_P256         0x0020
#endif

// Context to manage buffers across modules
typedef struct {
    uint8_t cmd_buf[512];
    uint8_t rsp_buf[2048];
    uint8_t *rsp_ptr;
    uint32_t rsp_size;
} TpmTestContext;

static const uint8_t platform_policy[32] = {
    0x16, 0x78, 0x60, 0xA3, 0x5F, 0x2C, 0x5C, 0x35,
    0x67, 0xF9, 0xC9, 0x27, 0xAC, 0x56, 0xC0, 0x32,
    0xF3, 0xB3, 0xA6, 0x46, 0x2F, 0x8D, 0x03, 0x79,
    0x98, 0xE7, 0xA1, 0x0F, 0x77, 0xFA, 0x45, 0x4A
};

/* =========================================================================
 * Platform Externs
 * ========================================================================= */
extern void _TPM_Init(void);
extern void _plat__RunCommand(uint32_t size, unsigned char *command, uint32_t *response_size, unsigned char **response);
extern void _plat__Signal_PowerOn(void);
extern void _plat__Signal_Reset(void);
extern void _plat__SetNvAvail(void);
extern void _plat__NVEnable(void *platParameter, uint32_t size);
extern int TPM_Manufacture(int firstTime);
extern bool _plat__NVNeedsManufacture(void);
extern void TPM_TearDown(void);

/* =========================================================================
 * Endianness Helpers (TPM 2.0 IS ALWAYS BIG-ENDIAN ON WIRE)
 * ========================================================================= */
static inline void write_be16(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)((v >> 8) & 0xFF); buf[1] = (uint8_t)(v & 0xFF);
}
static inline void write_be32(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)((v >> 24) & 0xFF); buf[1] = (uint8_t)((v >> 16) & 0xFF);
    buf[2] = (uint8_t)((v >> 8) & 0xFF);  buf[3] = (uint8_t)(v & 0xFF);
}
static inline uint16_t read_be16(const uint8_t *buf) {
    return (uint16_t)buf[1] | ((uint16_t)buf[0] << 8);
}
static inline uint32_t read_be32(const uint8_t *buf) {
    return (uint32_t)buf[3] | ((uint32_t)buf[2] << 8) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[0] << 24);
}

/* Utility printing */
void print_hex(const char *label, const uint8_t *data, uint32_t size) {
    printf("%s (%u bytes):\n", label, size);
    if (!data || size == 0) { printf("(empty)\n"); return; }
    for (uint32_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

const char* get_tpm_rc_name(uint32_t rc) {
    switch(rc) {
        case TPM_RC_SUCCESS: return "TPM_RC_SUCCESS";
        case TPM_RC_INITIALIZE: return "TPM_RC_INITIALIZE";
        case 0x00000095: return "TPM_RC_UNMARSHAL (Format Error)"; // Typical for GetRandom size error
        case 0x000001D5: return "TPM_RC_SIZE (Parameter 1)";
        case 0x000001C4: return "TPM_RC_VALUE (Parameter 1)";
        default: return "TPM_RC_ERROR";
    }
}

/* Helper to inject a Password Session (Empty Auth) into the command buffer */
/* Tag=0x8002 commands must include this area */
/* Returns the number of bytes written */
static uint32_t write_password_session(uint8_t *buf) {
    uint32_t off = 0;
    write_be32(buf + off, 9); off += 4;         // Authorization Size: 9 bytes
                                                       // (Handle(4) + NonceSize(2) + Attr(1) + AuthSize(2))
    // Session 1:
    write_be32(buf + off, 0x40000009); off += 4; // TPM_RS_PW (Password Session)
    write_be16(buf + off, 0); off += 2;          // Nonce Size (0)
    buf[off++] = 0x00;                                  // sessionAttributes (UINT8) = 0x00 (no ContinueSession)
                                                        // Use 0x00 (recommended) — 0x01 (ContinueSession) is usually ok but some TPM
                                                        // implementations are picky; use 0x00 to avoid surprises.
    write_be16(buf + off, 0); off += 2;          // Auth/HMAC Size (0) - Empty Password
    
    return off;
}

/* =========================================================================
 * Helper: Buffer Comparison
 * ========================================================================= */
static int compare_buffers(const char *label, const uint8_t *a, const uint8_t *b, uint32_t len)
{
    if (memcmp(a, b, len) == 0) {
        printf("✓ %s: Data verification passed\n", label);
        return 0;
    } else {
        printf("✗ %s: Data Mismatch!\n", label);
        printf("Expected (%u bytes):\n", len);
        for(int i=0;i<len;i++) { printf("%02X ", a[i]); if((i+1)%16==0) printf("\n"); } printf("\n");
        printf("Actual (%u bytes):\n", len);
        for(int i=0;i<len;i++) { printf("%02X ", b[i]); if((i+1)%16==0) printf("\n"); } printf("\n");
        return -1;
    }
}

/* Helper: parse TPM response header */
static int parse_tpm_resp_header(const uint8_t *rsp, uint32_t rsp_size,
                                 uint16_t *out_tag, uint32_t *out_size, uint32_t *out_rc)
{
    if (!rsp || rsp_size < 10) return -1;
    *out_tag  = read_be16(rsp + 0);
    *out_size = read_be32(rsp + 2);
    *out_rc   = read_be32(rsp + 6);
    return 0;
}

/* =========================================================================
 * Response Parsers (Corrected to use read_be)
 * ========================================================================= */
static void parse_GetCapability(const uint8_t *rsp_ptr, uint32_t rsp_size)
{
    uint16_t tag; uint32_t size; uint32_t rc;
    if (parse_tpm_resp_header(rsp_ptr, rsp_size, &tag, &size, &rc) != 0) return;

    printf("GetCapability RC = 0x%08X (%s)\n", rc, get_tpm_rc_name(rc));
    if (rc != TPM_RC_SUCCESS) return;

    if (rsp_size <= 10) return;

    /* Payload Structure:
       - moreData (BYTE)
       - capability (UINT32 BE)
       - properties (TPML_TAGGED_TPM_PROPERTY)
         - count (UINT32 BE)
         - property[0] (UINT32 BE)
         - value[0] (UINT32 BE)
    */
    uint32_t off = 10;
    
    // 1. moreData
    if (off + 1 <= rsp_size) {
        // uint8_t more = rsp_ptr[off];
        off += 1;
    }
    // 2. capability
    if (off + 4 <= rsp_size) {
        off += 4;
    }
    // 3. Property List
    if (off + 4 <= rsp_size) {
        /* FIX: Read count as BE32 */
        uint32_t count = read_be32(rsp_ptr + off);
        printf("GetCapability: property count = %u\n", count);
        off += 4;
        
        for (uint32_t i = 0; i < count && off + 8 <= rsp_size; i++) {
            /* FIX: Read prop/val as BE32 */
            uint32_t prop = read_be32(rsp_ptr + off); off += 4;
            uint32_t val  = read_be32(rsp_ptr + off); off += 4;
            printf("  property[%u] = 0x%08X => 0x%08X\n", i, prop, val);
        }
    }
}

static void parse_GetCapability_ALGS(const uint8_t *rsp, uint32_t size)
{
    printf("RSP TAG = %04X\n", read_be16(rsp));
    printf("RSP SIZE = %08X\n", read_be32(rsp + 2));
    printf("RSP RC = %08X\n", read_be32(rsp + 6));
    
    uint32_t rc = read_be32(rsp + 6);
    if (rc != 0) {
        printf("GetCapability(ALGS) RC=0x%08X\n", rc);
        return;
    }

    uint32_t off = 10; // 跳过响应头(10字节)
    
    // 注意：响应中没有parameterSize字段，只有命令中有
    uint8_t moreData = rsp[off++];
    printf("RSP moreData = %02X\n", moreData);
    
    uint32_t cap = read_be32(rsp + off); 
    off += 4;
    printf("RSP cap = %08X\n", cap);

    if (cap != TPM_CAP_ALGS) {
        printf("Not ALGS capability! Expected 0x%08X, got 0x%08X\n", TPM_CAP_ALGS, cap);
        return;
    }

    // TPML_ALG_PROPERTY.count (4 bytes)
    uint32_t count = read_be32(rsp + off); 
    off += 4;
    printf("ALGS count = %u\n", count);

    for (uint32_t i = 0; i < count && off + 6 <= size; i++) {
        uint16_t algId = read_be16(rsp + off); 
        off += 2;
        
        // TPMA_ALGORITHM 是4字节
        uint32_t algProps = read_be32(rsp + off); 
        off += 4;

        printf("ALG 0x%04X:", algId);
        if (algProps & 1) printf(" hash");
        if (algProps & 2) printf(" object");
        printf("\n");
    }
}

static void parse_PCR_Read(const uint8_t *rsp_ptr, uint32_t rsp_size)
{
    uint16_t tag; uint32_t size; uint32_t rc;
    if (parse_tpm_resp_header(rsp_ptr, rsp_size, &tag, &size, &rc) != 0) return;

    printf("PCR_Read RC = 0x%08X (%s)\n", rc, get_tpm_rc_name(rc));
    if (rc != TPM_RC_SUCCESS) return;

    /* Payload Structure:
       - pcrUpdateCounter (UINT32 BE)
       - pcrSelectionOut (TPML_PCR_SELECTION)
       - pcrValues (TPML_DIGEST)
         - count (UINT32 BE)
         - digests (TPM2B_DIGEST...) -> Size(BE16) + Buffer
    */
    uint32_t off = 10;

    // 1. Update Counter
    if (off + 4 <= rsp_size) {
        uint32_t counter = read_be32(rsp_ptr + off);
        printf("PCR_Read: pcrUpdateCounter = %u\n", counter);
        off += 4;
    }

    // 2. Selection Out (Skip logic for simplicity)
    if (off + 4 <= rsp_size) {
        uint32_t count = read_be32(rsp_ptr + off); // pcrSelectionOut.count
        off += 4;
        // Skip selections: each is hash(2) + size(1) + bitmap(N)
        // Since we know we asked for SHA256 (3 bytes), we jump 6 bytes * count
        off += count * 6; 
    }

    // 3. Digest Values
    if (off + 4 <= rsp_size) {
        /* FIX: Read digest count as BE32 */
        uint32_t digestCount = read_be32(rsp_ptr + off);
        printf("PCR_Read: digestCount = %u\n", digestCount);
        off += 4;

        for (uint32_t i = 0; i < digestCount; i++) {
            if (off + 2 > rsp_size) break;
            /* FIX: Read size as BE16 */
            uint16_t dSize = read_be16(rsp_ptr + off);
            off += 2;

            if (off + dSize > rsp_size) {
                printf("PCR_Read: truncated digest bytes\n");
                break;
            }
            // Only print first few bytes to avoid clutter
            printf("  digest[%u] size=%u: ", i, dSize);
            for(int k=0; k<((dSize>8)?8:dSize); k++) printf("%02X ", rsp_ptr[off+k]);
            printf("...\n");
            off += dSize;
        }
    }
}

static void parse_SelfTest(const uint8_t *rsp_ptr, uint32_t rsp_size)
{
    uint16_t tag; uint32_t size; uint32_t rc;
    parse_tpm_resp_header(rsp_ptr, rsp_size, &tag, &size, &rc);
    printf("SelfTest RC = 0x%08X (%s)\n", rc, get_tpm_rc_name(rc));
}


/* * Core Execution Wrapper 
 * Sends command, receives response, checks RC.
 * Returns: RC (uint32)
 */
static uint32_t TpmSendCmd(TpmTestContext *ctx, uint32_t cmd_len, const char *desc) {
    if (desc) print_hex(desc, ctx->cmd_buf, cmd_len);
    
    ctx->rsp_size = sizeof(ctx->rsp_buf);
    ctx->rsp_ptr = ctx->rsp_buf;
    memset(ctx->rsp_buf, 0, ctx->rsp_size);
    
    _plat__RunCommand(cmd_len, ctx->cmd_buf, &ctx->rsp_size, &ctx->rsp_ptr);
    
    if (!ctx->rsp_ptr || ctx->rsp_size < 10) {
        printf("Error: No response or response too short\n");
        return 0xFFFFFFFF;
    }
    
    uint32_t rc = read_be32(ctx->rsp_ptr + 6);
    if (rc != TPM_RC_SUCCESS) {
        printf("%s Failed: 0x%08X\n", desc ? desc : "Command", rc);
    }
    return rc;
}

// 内部工具：将单个 hex 字符转换为数值
static uint8_t hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

/*
 * 解析 Hex 字符串并发送命令
 * 支持格式： "80 01...", "8001...", "0x80, 0x01..." 以及换行符
 */
void RunRawHexCmd(TpmTestContext *ctx, const char *hexStr, const char *desc)
{
    uint32_t len = 0;
    const char *p = hexStr;
    uint8_t *buf = ctx->cmd_buf;
    
    // 1. 清理并解析 Hex 字符串到 cmd_buf
    while (*p) {
        // 跳过空格、换行、制表符、逗号
        if (isspace((int)*p) || *p == ',') {
            p++;
            continue;
        }
        // 跳过 "0x" 前缀
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            p += 2;
            continue;
        }

        // 读取两个字符作为 1 个字节
        if (isxdigit((int)p[0]) && isxdigit((int)p[1])) {
            uint8_t hi = hexCharToInt(*p++);
            uint8_t lo = hexCharToInt(*p++);
            
            if (len < sizeof(ctx->cmd_buf)) {
                buf[len++] = (hi << 4) | lo;
            } else {
                printf("Error: Command buffer overflow!\n");
                return;
            }
        } else {
            // 遇到非 Hex 字符，停止或报错，这里选择跳过
            p++;
        }
    }

    // 2. 打印调试信息
    printf("\n--- Send Raw Hex: %s ---\n", desc);
    printf("Parsed Length: %d bytes\n", len);

    // 3. 调用现有的发送函数
    // TpmSendCmd 会负责发送 cmd_buf 中的数据并接收响应
    TpmSendCmd(ctx, len, desc);
    
    // 4. (可选) 如果是 Create/Load 命令，你可能需要手动解析 Handle
    // 这里简单的打印一下响应的前几个字节看看结果
    if (len > 0) {
        uint32_t rc = read_be32(ctx->rsp_ptr + 6);
        if (rc == TPM_RC_SUCCESS) {
            printf("✓ Raw Command Executed Successfully.\n");
            // 如果是 CreatePrimary/Load，Handle 通常在偏移 14
            // uint32_t handle = read_be32(ctx->rsp_ptr + 14);
            // printf("  Handle output: 0x%08X\n", handle);
        } else {
            printf("✗ Raw Command Failed: 0x%08X\n", rc);
        }
    }
}

/* =========================================================================
 * Test Modules
 * ========================================================================= */

void Test_Startup(TpmTestContext *ctx) {
    printf("\n--- Test 1: TPM2_Startup (CLEAR) ---\n");
    uint32_t off = 0;
    write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
    write_be32(ctx->cmd_buf + off, 12); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_CC_Startup); off += 4;
    write_be16(ctx->cmd_buf + off, TPM_SU_CLEAR); off += 2;

    if (TpmSendCmd(ctx, off, "Sending Startup(CLEAR)") == TPM_RC_SUCCESS) {
        printf("✓ Startup Successful\n");
    }
}

void Test_SelfTest(TpmTestContext *ctx) {
    printf("\n--- Test 2: TPM2_SelfTest ---\n");
    uint32_t off = 0;
    write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
    write_be32(ctx->cmd_buf + off, 11); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_CC_SelfTest); off += 4;
    ctx->cmd_buf[off++] = 0x01; // Full Test

    if (TpmSendCmd(ctx, off, "Sending SelfTest") == TPM_RC_SUCCESS) {
        printf("✓ SelfTest Successful\n");
    }
}

void Test_GetRandom(TpmTestContext *ctx) {
    printf("\n--- Test 3: TPM2_GetRandom ---\n");
    uint32_t off = 0;
    write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
    write_be32(ctx->cmd_buf + off, 12); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_CC_GetRandom); off += 4;
    write_be16(ctx->cmd_buf + off, 16); off += 2;

    if (TpmSendCmd(ctx, off, "Sending GetRandom") == TPM_RC_SUCCESS) {
        // Parse
        uint16_t r_size = read_be16(ctx->rsp_ptr + 10);
        print_hex("Random Data", ctx->rsp_ptr + 12, r_size);
        
        int all_zeros = 1;
        for(int i=0; i<r_size; i++) if(ctx->rsp_ptr[12+i] != 0) all_zeros = 0;
        
        if (!all_zeros) printf("✓ Entropy Detected\n");
        else printf("!!! WARNING: Random data is all zeros\n");
    }
}

void Test_PCR_Read(TpmTestContext *ctx) {
    printf("\n--- Test 4: TPM2_PCR_Read ---\n");
    uint32_t off = 0;
    write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
    write_be32(ctx->cmd_buf + off, 20); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_CC_PCR_Read); off += 4;
    
    // PCR Selection: Count 1, SHA256, Size 3, PCR 0
    uint8_t *p = ctx->cmd_buf + off;
    write_be32(p, 1); p += 4;
    write_be16(p, TPM_ALG_SM3_256); p += 2;
    *p++ = 3; *p++ = 0x01; *p++ = 0x00; *p++ = 0x00;
    off = p - ctx->cmd_buf;

    if (TpmSendCmd(ctx, off, "Sending PCR_Read") == TPM_RC_SUCCESS) {
        // Simple Parse to show update counter
        // uint32_t updateCnt = read_be32(ctx->rsp_ptr + 10);
        // printf("PCR Update Counter: %u\n", updateCnt);
        // printf("✓ PCR Read OK\n");
        parse_PCR_Read(ctx->rsp_ptr, ctx->rsp_size);
    }
}

void Test_GetCapability(TpmTestContext *ctx) {
    printf("\n--- Test 5: TPM2_GetCapability ---\n");
    uint32_t off = 0;
    write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
    write_be32(ctx->cmd_buf + off, 22); off += 4;    // TPM_CAP_TPM_PROPERTIES   
    write_be32(ctx->cmd_buf + off, TPM_CC_GetCapability); off += 4;
    
    /* write_be32(ctx->cmd_buf + off, TPM_CAP_TPM_PROPERTIES); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_PT_FIXED); off += 4;
    write_be32(ctx->cmd_buf + off, 1); off += 4; */

    write_be32(ctx->cmd_buf + off, TPM_CAP_ALGS); off += 4;
    write_be32(ctx->cmd_buf + off, 0x00000000); off += 4;
    write_be32(ctx->cmd_buf + off, 0x0000002E); off += 4;

    if (TpmSendCmd(ctx, off, "Sending GetCap") == TPM_RC_SUCCESS) {
        // parse_GetCapability(ctx->rsp_ptr, ctx->rsp_size);
        parse_GetCapability_ALGS(ctx->rsp_ptr, ctx->rsp_size);
    }
}

void Test_Hash(TpmTestContext *ctx) {
    printf("\n--- Test 6: TPM2_Hash ---\n");
    const char *input = "123456";
    uint32_t off = 0;
    write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
    uint32_t size_off = off; off += 4;
    write_be32(ctx->cmd_buf + off, TPM_CC_Hash); off += 4;
    
    write_be16(ctx->cmd_buf + off, 6); off += 2;
    memcpy(ctx->cmd_buf + off, input, 6); off += 6;
    write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2;
    write_be32(ctx->cmd_buf + off, 0x40000001); off += 4; // Owner
    
    write_be32(ctx->cmd_buf + size_off, off);

    if (TpmSendCmd(ctx, off, "Sending Hash") == TPM_RC_SUCCESS) {
        // Header(10) + Size(2) + Digest
        uint16_t d_size = read_be16(ctx->rsp_ptr + 10);
        printf("Hash Size: %u\n", d_size);
        const uint8_t expected[] = {
            0x20, 0x7C, 0xF4, 0x10, 0x53, 0x2F, 0x92, 0xA4, 0x7D, 0xEE, 0x24, 0x5C, 0xE9, 0xB1, 0x1F, 0xF7,
            0x1F, 0x57, 0x8E, 0xBD, 0x76, 0x3E, 0xB3, 0xBB, 0xEA, 0x44, 0xEB, 0xD0, 0x43, 0xD0, 0x18, 0xFB
        };
        print_hex("Expected Hash", expected, sizeof(expected));
        print_hex("Actual Hash", ctx->rsp_ptr + 12, 32);
        compare_buffers("Hash Result", expected, ctx->rsp_ptr + 12, 32);
    }
}

void Test_NV_Storage(TpmTestContext *ctx) {
    printf("\n--- Test 7: NV Storage (Index 0x01500002) ---\n");
    uint32_t nv_index = 0x01500002;
    uint32_t nv_size = 8;
    const uint8_t test_data[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
    
    // 1. DefineSpace
    {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_NV_DefineSpace); off += 4;
        write_be32(ctx->cmd_buf + off, 0x40000001); off += 4; // Owner
        off += write_password_session(ctx->cmd_buf + off);
        
        write_be16(ctx->cmd_buf + off, 0); off += 2; // Auth Size
        uint32_t pub_size_off = off; off += 2;
        uint32_t pub_start = off;
        
        write_be32(ctx->cmd_buf + off, nv_index); off += 4;
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2;
        // Attr: OwnerWrite|OwnerRead|AuthRead|AuthWrite 0x00060006
        write_be32(ctx->cmd_buf + off, 0x00060006); off += 4;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be16(ctx->cmd_buf + off, nv_size); off += 2;
        
        write_be16(ctx->cmd_buf + pub_size_off, off - pub_start);
        write_be32(ctx->cmd_buf + size_off, off);
        
        uint32_t rc = TpmSendCmd(ctx, off, "DefineSpace");
        if (rc != TPM_RC_SUCCESS && rc != TPM_RC_NV_DEFINED) return;
        if (rc == TPM_RC_NV_DEFINED) printf("NV already defined.\n");
    }
    
    // 2. Write
    {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_NV_Write); off += 4;
        write_be32(ctx->cmd_buf + off, 0x40000001); off += 4; // Owner
        write_be32(ctx->cmd_buf + off, nv_index);   off += 4;
        off += write_password_session(ctx->cmd_buf + off);
        
        write_be16(ctx->cmd_buf + off, 8); off += 2;
        memcpy(ctx->cmd_buf + off, test_data, 8); off += 8;
        write_be16(ctx->cmd_buf + off, 0); off += 2; // Offset
        write_be32(ctx->cmd_buf + size_off, off);
        
        if (TpmSendCmd(ctx, off, "NV_Write") != TPM_RC_SUCCESS) return;
    }

    // 3. Read
    {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_NV_Read); off += 4;
        write_be32(ctx->cmd_buf + off, 0x40000001); off += 4;
        write_be32(ctx->cmd_buf + off, nv_index);   off += 4;
        off += write_password_session(ctx->cmd_buf + off);
        
        write_be16(ctx->cmd_buf + off, 8); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be32(ctx->cmd_buf + size_off, off);
        
        if (TpmSendCmd(ctx, off, "NV_Read") == TPM_RC_SUCCESS) {
            // Header(10) + ParamSize(4) + Size(2) + Data
            uint16_t r_len = read_be16(ctx->rsp_ptr + 14);
            compare_buffers("NV Verify", test_data, ctx->rsp_ptr + 16, r_len);
        }
    }
}

void Test_SM2_Hierarchy(TpmTestContext *ctx) {
    printf("\n--- Test 8: SM2 Hierarchy (SM2 SRK -> SM2 Sign Child) ---\n");
    
    uint32_t srk_handle = 0;
    uint32_t child_handle = 0;
    
    // Buffers for child blob
    static uint8_t priv_blob[256]; static uint16_t priv_size = 0;
    static uint8_t pub_blob[256];  static uint16_t pub_size = 0;

    // --------------------------------------------------------
    // 1. CreatePrimary (SM2 SRK - Restricted/Decrypt)
    // --------------------------------------------------------
    {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_CreatePrimary); off += 4;
        write_be32(ctx->cmd_buf + off, 0x40000001); off += 4; // Owner  // 40000007
        off += write_password_session(ctx->cmd_buf + off);

        // Sensitive
        write_be16(ctx->cmd_buf + off, 4); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        // Public (SM2 SRK)
        uint32_t pub_size_off = off; off += 2;
        uint32_t pub_start = off;

        write_be16(ctx->cmd_buf + off, 0x0023); off += 2; // TPM_ALG_ECC
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2; // NameAlg = SM3

        // Attr: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|adminWithPolicy|Decrypt|Restricted
        write_be32(ctx->cmd_buf + off, 0x000300F2); off += 4;

        // authPolicy
        // write_be16(ctx->cmd_buf + off, 0); off += 2; // Policy
        // 在 CreatePrimary 的 Public 结构中，在 objectAttributes 之后、parameters 之前
        write_be16(ctx->cmd_buf + off, 32); off += 2; // authPolicy.size = 32
        memcpy(ctx->cmd_buf + off, platform_policy, 32); off += 32; // buffer = PolicyBSM3_256

        // ECC Params for SRK
        // Symmetric: MUST be SM4 (0x0013) for TCM
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM4); off += 2;
        write_be16(ctx->cmd_buf + off, 0x0080); off += 2;  // keyBits = 128
        write_be16(ctx->cmd_buf + off, TPM_ALG_CFB); off += 2;  // mode = CFB

        // Scheme: Null
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2; 
        // Curve: SM2_P256 (0x0020)
        write_be16(ctx->cmd_buf + off, TPM_ECC_SM2_P256); off += 2; 
        // KDF: KDF_CTR_HMAC_SM3 (Algorithm 0x0022, Hash 0x0012)
        // write_be16(ctx->cmd_buf + off, TPM_ALG_KDF_CTR); off += 2; 
        // write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2;
        // KDF: Should be NULL according to template
        // write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2; 
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2; 

        write_be16(ctx->cmd_buf + off, 0); off += 2; // Unique X
        write_be16(ctx->cmd_buf + off, 0); off += 2; // Unique Y

        write_be16(ctx->cmd_buf + pub_size_off, off - pub_start);
        write_be16(ctx->cmd_buf + off, 0); off += 2; // OutsideInfo
        write_be32(ctx->cmd_buf + off, 0); off += 4; // PCR

        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "CreatePrimary (SM2 SRK)") == TPM_RC_SUCCESS) {
            srk_handle = read_be32(ctx->rsp_ptr + 14);
            printf("✓ SM2 SRK Handle: 0x%08X\n", srk_handle);
        } else {
            return;
        }
    }
    // --------------------------------------------------------
    // 2. Create Child (SM2 Signing Key) - Based on Template H-13
    // --------------------------------------------------------
    if (srk_handle) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_Create); off += 4;
        write_be32(ctx->cmd_buf + off, srk_handle); off += 4;
        
        off += write_password_session(ctx->cmd_buf + off);

        // Sensitive
        write_be16(ctx->cmd_buf + off, 4); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        // Public (SM2 Sign) - Based on Template H-13
        uint32_t pub_size_off = off; off += 2;
        uint32_t pub_start = off;

        // type
        write_be16(ctx->cmd_buf + off, TPM_ALG_ECC); off += 2; // 0x0023

        // nameAlg
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2; // 0x0012

        // Attr: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|adminWithPolicy|Restricted|Sign
        write_be32(ctx->cmd_buf + off, 0x000500F2); off += 4;

        write_be16(ctx->cmd_buf + off, 32); off += 2; // size = 32
        memcpy(ctx->cmd_buf + off, platform_policy, 32); off += 32; // buffer

        // parameters
        // symmetric->algorithm = NULL
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2;

        // scheme->scheme = SM2
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM2); off += 2; // 0x001B

        // scheme->details.hashAlg = SM3
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2; // 0x0012

        // curveID = SM2_P256
        write_be16(ctx->cmd_buf + off, TPM_ECC_SM2_P256); off += 2; // 0x0020

        // kdf->scheme = NULL
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2;

        // unique.x.size = 0
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        // unique.y.size = 0
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        // Write public area size
        write_be16(ctx->cmd_buf + pub_size_off, off - pub_start);

        // OutsideInfo & PCR
        write_be16(ctx->cmd_buf + off, 0); off += 2; // OutsideInfo
        write_be32(ctx->cmd_buf + off, 0); off += 4; // PCR

        // Finalize command size
        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "TPM2_Create (SM2 Child)") == TPM_RC_SUCCESS) {
            // Save blobs
            uint32_t r_off = 14;
            priv_size = read_be16(ctx->rsp_ptr + r_off); r_off += 2;
            memcpy(priv_blob, ctx->rsp_ptr + r_off, priv_size); r_off += priv_size;
            
            pub_size = read_be16(ctx->rsp_ptr + r_off); r_off += 2;
            memcpy(pub_blob, ctx->rsp_ptr + r_off, pub_size);
            printf("✓ SM2 Child Created\n");
        }
    }
    // --------------------------------------------------------
    // 2. Create Child (SM2 General Signing Key)
    // --------------------------------------------------------
    /* if (srk_handle) {
        uint32_t off = 0;
        
        // 1. Header
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_Create); off += 4; // TPM2_Create
        
        // 2. Handles
        write_be32(ctx->cmd_buf + off, srk_handle); off += 4; // Parent Handle
        
        // 3. Auth Session
        off += write_password_session(ctx->cmd_buf + off);

        // 4. Parameters
        
        // --- inSensitive ---
        // authSize(2) + auth + dataSize(2) + data
        uint32_t sens_start = off; off += 2; // Size placeholder
        write_be16(ctx->cmd_buf + off, 0); off += 2; // userAuth size (0)
        write_be16(ctx->cmd_buf + off, 0); off += 2; // data size (0)
        write_be16(ctx->cmd_buf + sens_start, (uint16_t)(off - sens_start - 2)); // Fill size

        // --- inPublic (The Template) ---
        uint32_t pub_size_off = off; off += 2; // Size placeholder
        uint32_t pub_start = off;
        
        write_be16(ctx->cmd_buf + off, 0x0023); off += 2; // Type: ECC
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2; // NameAlg: SM3
        
    
        write_be32(ctx->cmd_buf + off, 0x00040072); off += 4;
        
        write_be16(ctx->cmd_buf + off, 0); off += 2; // AuthPolicy Size (0)
        
        // --- ECC Parameters ---
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2; // Symmetric: NULL
        
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2; 
        
        write_be16(ctx->cmd_buf + off, TPM_ECC_SM2_P256); off += 2; // Curve: SM2_P256
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2; // KDF: NULL
        
        // Unique (X, Y)
        write_be16(ctx->cmd_buf + off, 0); off += 2; // X size 0
        write_be16(ctx->cmd_buf + off, 0); off += 2; // Y size 0
        
        // Fill Public Size
        write_be16(ctx->cmd_buf + pub_size_off, (uint16_t)(off - pub_start));
        
        // --- outsideInfo ---
        write_be16(ctx->cmd_buf + off, 0); off += 2; 
        
        // --- creationPCR ---
        write_be32(ctx->cmd_buf + off, 0); off += 4; // Count 0
        
        // Finalize Command Size
        write_be32(ctx->cmd_buf + size_off, off);
        
        printf("Sending TPM2_Create (SM2 Child, General Signing)...\n");
        ctx->rsp_size = sizeof(ctx->rsp_buf); memset(ctx->rsp_buf, 0, ctx->rsp_size);
        if (TpmSendCmd(ctx, off, "TPM2_Create (SM2 Child)") == TPM_RC_SUCCESS) {
            printf("✓ Child Key Created (Blob generated).\n");
            
            // Response Parsing: Header(10) + ParamSize(4) + outPrivate + outPublic ...
            uint32_t r_off = 14; 
            
            // outPrivate
            priv_size = read_be16(ctx->rsp_ptr + r_off); r_off += 2;
            memcpy(priv_blob, ctx->rsp_ptr + r_off, priv_size); r_off += priv_size;
            
            // outPublic
            pub_size = read_be16(ctx->rsp_ptr + r_off); r_off += 2;
            memcpy(pub_blob, ctx->rsp_ptr + r_off, pub_size);
            
            // Debug info
            printf("  PrivSize: %d, PubSize: %d\n", priv_size, pub_size);
        }
    } */

    // --------------------------------------------------------
    // 3. Load Child
    // --------------------------------------------------------
    if (priv_size > 0) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, 0x00000157); off += 4; // TPM2_Load
        write_be32(ctx->cmd_buf + off, srk_handle); off += 4;
        off += write_password_session(ctx->cmd_buf + off);

        write_be16(ctx->cmd_buf + off, priv_size); off += 2;
        memcpy(ctx->cmd_buf + off, priv_blob, priv_size); off += priv_size;

        write_be16(ctx->cmd_buf + off, pub_size); off += 2;
        memcpy(ctx->cmd_buf + off, pub_blob, pub_size); off += pub_size;

        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "TPM2_Load") == TPM_RC_SUCCESS) {
            child_handle = read_be32(ctx->rsp_ptr + 14);
            printf("✓ Child Loaded. Handle: 0x%08X\n", child_handle);
        }
    }

    // --------------------------------------------------------
    // 4. Sign (SM3 Digest)
    // --------------------------------------------------------
    if (child_handle) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, 0x0000015D); off += 4; // Sign
        write_be32(ctx->cmd_buf + off, child_handle); off += 4;
        off += write_password_session(ctx->cmd_buf + off);

        // Digest (SM3 is 32 bytes)
        write_be16(ctx->cmd_buf + off, 32); off += 2;
        memset(ctx->cmd_buf + off, 0xAA, 32); off += 32; // Dummy digest

        // Scheme: SM2 (0x001B) or ECDSA (0x0018) + SM3
        // Note: Some TCM implementations map ECDSA to SM2 signature.
        // Let's try Null Scheme to let Key decide.
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; 
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; 

        // Validation
        write_be16(ctx->cmd_buf + off, 0x8004); off += 2;
        write_be32(ctx->cmd_buf + off, 0x40000007); off += 4;
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "Sign (SM2)") == TPM_RC_SUCCESS) {
            printf("✓ SM2 Signature Generated!\n");
        }
        
        // Flush child...
    }
    // Flush SRK...
}


void Test_SM2_Hierarchy2(TpmTestContext *ctx) {
    printf("\n--- Test 8: SM2 Hierarchy (SM2 SRK -> SM2 Sign Child) ---\n");
    
    uint32_t srk_handle = 0;
    uint32_t child_handle = 0;
    
    // Buffers for child blob
    static uint8_t priv_blob[256]; static uint16_t priv_size = 0;
    static uint8_t pub_blob[256];  static uint16_t pub_size = 0;

    // --------------------------------------------------------
    // 1. CreatePrimary (SM2 SRK - Restricted/Decrypt)
    // --------------------------------------------------------
    /* CreatePrimary：SM2 SRK, Restricted/Decrypt, symmetric=SM4-128-CFB, kdf=KDF1_SP800_108(SM3) */
    {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_CreatePrimary); off += 4;

        // parent = Owner
        write_be32(ctx->cmd_buf + off, 0x40000001); off += 4;

        // auth area (password session, empty auth)
        off += write_password_session(ctx->cmd_buf + off);

        // TPM2B_SENSITIVE_CREATE (size + userAuth + data) - empty userAuth/data
        uint32_t sens_start = off; off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2; // userAuth size = 0
        write_be16(ctx->cmd_buf + off, 0); off += 2; // data size = 0
        write_be16(ctx->cmd_buf + sens_start, (uint16_t)(off - (sens_start + 2)));

        // TPM2B_PUBLIC (size placeholder)
        uint32_t pub_size_off = off; off += 2;
        uint32_t pub_start = off;

        // TPMT_PUBLIC.type  = ECC (0x0023)
        write_be16(ctx->cmd_buf + off, TPM_ALG_ECC); off += 2;
        // nameAlg = SM3 (0x0012)
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2;

        // objectAttributes: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|Restricted|Decrypt
        write_be32(ctx->cmd_buf + off, 0x00030072); off += 4;

        // authPolicy (TPM2B) empty
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        /* TPMT_ECC_PARMS:
        symmetric (TPMT_SYM_DEF_OBJECT) -> SM4 (0x0013), keyBits=128, mode=CFB (0x0043)
        scheme (TPMT_ECC_SCHEME) -> TPM_ALG_NULL
        curveID -> TPM_ECC_SM2_P256
        kdf -> TPM_ALG_KDF1_SP800_108 (0x0022) with hash = SM3 (0x0012)
        */

        // symmetric.alg = SM4
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM4); off += 2;
        // symmetric details: keyBits (UINT16) then mode (UINT16)
        write_be16(ctx->cmd_buf + off, 128); off += 2;        // keyBits
        write_be16(ctx->cmd_buf + off, TPM_ALG_CFB); off += 2; // mode CFB (0x0043)

        // scheme = NULL
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2;

        // curveID = SM2_P256 (macro)
        write_be16(ctx->cmd_buf + off, TPM_ECC_SM2_P256); off += 2;

        // kdf = KDF1_SP800_108 (0x0022) + hash = SM3 (0x0012)
        // write_be16(ctx->cmd_buf + off, TPM_ALG_KDF_CTR); off += 2;
        // write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2;
        // kdf = TPM_ALG_NULL
        write_be16(ctx->cmd_buf + off, TPM_ALG_NULL); off += 2;

        // unique (TPM2B_ECC_POINT) - x/y empty
        write_be16(ctx->cmd_buf + off, 0); off += 2; // x size = 0
        write_be16(ctx->cmd_buf + off, 0); off += 2; // y size = 0

        // Fill TPM2B_PUBLIC.size
        write_be16(ctx->cmd_buf + pub_size_off, (uint16_t)(off - (pub_start + 2)));

        // outsideInfo empty
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        // creationPCR: count 0
        write_be32(ctx->cmd_buf + off, 0); off += 4;

        // finalize
        write_be32(ctx->cmd_buf + size_off, off);

        printf("Sending CreatePrimary (SM2 SRK w/ SM4/CFB + KDF) ...\n");
        if (TpmSendCmd(ctx, off, "CreatePrimary (SM2 SRK)") == TPM_RC_SUCCESS) {
            srk_handle = read_be32(ctx->rsp_ptr + 14);
            printf("✓ SM2 SRK Handle: 0x%08X\n", srk_handle);
        } else {
            printf("CreatePrimary (SM2 SRK) failed\n");
            return;
        }
    }

    // --------------------------------------------------------
    // 2. Create Child (SM2 Signing Key)
    // --------------------------------------------------------
    if (srk_handle) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, 0x00000153); off += 4; // TPM2_Create
        write_be32(ctx->cmd_buf + off, srk_handle); off += 4;
        off += write_password_session(ctx->cmd_buf + off);

        // Sensitive
        write_be16(ctx->cmd_buf + off, 4); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        // Public (SM2 Sign)
        uint32_t pub_size_off = off; off += 2;
        uint32_t pub_start = off;

        write_be16(ctx->cmd_buf + off, 0x0023); off += 2; // ECC
        write_be16(ctx->cmd_buf + off, TPM_ALG_SM3_256); off += 2; // NameAlg

        // Attr: Sign|FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth
        write_be32(ctx->cmd_buf + off, 0x00040072); off += 4;

        write_be16(ctx->cmd_buf + off, 0); off += 2; // Policy

        // ECC Params
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; // Sym: Null
        write_be16(ctx->cmd_buf + off, 0x0018); off += 2; // Scheme: ECDSA (Used for SM2)
        write_be16(ctx->cmd_buf + off, TPM_ECC_SM2_P256); off += 2; // Curve: SM2
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; // KDF: Null

        write_be16(ctx->cmd_buf + off, 0); off += 2; // Unique
        write_be16(ctx->cmd_buf + off, 0); off += 2; 

        write_be16(ctx->cmd_buf + pub_size_off, off - pub_start);
        write_be16(ctx->cmd_buf + off, 0); off += 2; // OutsideInfo
        write_be32(ctx->cmd_buf + off, 0); off += 4; // PCR

        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "TPM2_Create (SM2 Child)") == TPM_RC_SUCCESS) {
            // Save blobs
            uint32_t r_off = 14;
            priv_size = read_be16(ctx->rsp_ptr + r_off); r_off += 2;
            memcpy(priv_blob, ctx->rsp_ptr + r_off, priv_size); r_off += priv_size;
            
            pub_size = read_be16(ctx->rsp_ptr + r_off); r_off += 2;
            memcpy(pub_blob, ctx->rsp_ptr + r_off, pub_size);
            printf("✓ SM2 Child Created\n");
        }
    }

    // --------------------------------------------------------
    // 3. Load Child
    // --------------------------------------------------------
    if (priv_size > 0) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, 0x00000157); off += 4; // TPM2_Load
        write_be32(ctx->cmd_buf + off, srk_handle); off += 4;
        off += write_password_session(ctx->cmd_buf + off);

        write_be16(ctx->cmd_buf + off, priv_size); off += 2;
        memcpy(ctx->cmd_buf + off, priv_blob, priv_size); off += priv_size;

        write_be16(ctx->cmd_buf + off, pub_size); off += 2;
        memcpy(ctx->cmd_buf + off, pub_blob, pub_size); off += pub_size;

        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "TPM2_Load") == TPM_RC_SUCCESS) {
            child_handle = read_be32(ctx->rsp_ptr + 14);
            printf("✓ Child Loaded. Handle: 0x%08X\n", child_handle);
        }
    }

    // --------------------------------------------------------
    // 4. Sign (SM3 Digest)
    // --------------------------------------------------------
    if (child_handle) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, 0x0000015D); off += 4; // Sign
        write_be32(ctx->cmd_buf + off, child_handle); off += 4;
        off += write_password_session(ctx->cmd_buf + off);

        // Digest (SM3 is 32 bytes)
        write_be16(ctx->cmd_buf + off, 32); off += 2;
        memset(ctx->cmd_buf + off, 0xAA, 32); off += 32; // Dummy digest

        // Scheme: SM2 (0x001B) or ECDSA (0x0018) + SM3
        // Note: Some TCM implementations map ECDSA to SM2 signature.
        // Let's try Null Scheme to let Key decide.
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; 
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; 

        // Validation
        write_be16(ctx->cmd_buf + off, 0x8004); off += 2;
        write_be32(ctx->cmd_buf + off, 0x40000007); off += 4;
        write_be16(ctx->cmd_buf + off, 0); off += 2;

        write_be32(ctx->cmd_buf + size_off, off);

        if (TpmSendCmd(ctx, off, "Sign (SM2)") == TPM_RC_SUCCESS) {
            printf("✓ SM2 Signature Generated!\n");
        }
        
        // Flush child...
    }
    // Flush SRK...
}

void Test_Replay_Capture_CreatePrimary(TpmTestContext *ctx) {
    // ./createprimary -hi p -ecc sm2p256 -st -pwdk sto  -tk tk.bin -ch ch.bin -halg sm3 -nalg sm3
    const char *captured_cmd = 
        "80 02 00 00 00 46 00 00 01 31 40 00 00 0c 00 00 "
        "00 09 40 00 00 09 00 00 00 00 00 00 07 00 03 73 "
        "74 6f 00 00 00 1a 00 23 00 12 00 03 04 72 00 00 "
        "00 13 00 80 00 43 00 10 00 20 00 10 00 00 00 00 "
        "00 00 00 00 00 00";

    RunRawHexCmd(ctx, captured_cmd, "Replay Captured CreatePrimary");
}

void Test_Replay_Capture_Create(TpmTestContext *ctx) {
    // ./create -hp 80000000 -ecc sm2p256 -si -halg sm3 -kt f -kt p -opr signeccpriv.bin -opu signeccpub.bin  -pwdp sto -pwdk sig -nalg sm3
    const char *captured_cmd = 
        "80 02 00 00 00 45 00 00 01 53 80 00 00 00 00 00 "
        "00 0c 40 00 00 09 00 00 00 00 03 73 74 6f 00 07 " 
        "00 03 73 69 67 00 00 00 16 00 23 00 12 00 04 04 "
        "72 00 00 00 10 00 10 00 20 00 10 00 00 00 00 00 "
        "00 00 00 00 00 ";

    RunRawHexCmd(ctx, captured_cmd, "Replay Captured Create");
}

void Test_Replay_Capture_Load(TpmTestContext *ctx) {
    // ./load -hp 80000000 -ipr signeccpriv.bin -ipu signeccpub.bin -pwdp sto
    /* const char *captured_cmd = 
        "80 02 00 00 00 f6 00 00 01 57 80 00 00 00 00 00 " 
        "00 0c 40 00 00 09 00 00 00 00 03 73 74 6f 00 7e "
        "00 20 ff 4e 8f ab dd da 2d 6a cf c7 ca 10 a2 f3 "
        "30 30 4b 44 3c d7 11 e7 6e de 08 e8 a2 84 35 e6 "
        "b9 e6 00 10 04 32 9c 03 2c 94 59 d9 c3 c3 9c 28 "
        "1b 3c 8f 8e b2 88 5e e2 6c 06 46 38 93 d6 f8 30 "
        "6b 5c 48 5d 04 74 95 51 40 c7 59 2e 93 68 8f 14 "
        "38 35 6c 41 93 ba fc 11 02 58 61 f8 20 32 c0 b0 "
        "f4 85 0c e7 f1 c0 1f dc 35 03 01 5e 08 34 b7 8e "
        "f4 f0 a3 8a 72 ed 22 01 27 08 0d 44 04 3d 00 56 "
        "00 23 00 12 00 04 04 72 00 00 00 10 00 10 00 20 "
        "00 10 00 20 0d e2 b0 46 17 ba bf 9c d1 bd 6c 9f "
        "1a d5 22 d8 95 2c 88 47 2f df 58 f0 26 f6 16 74 "
        "6b 95 4b 42 00 20 f4 99 a8 d1 6a e3 c6 02 7e 85 "
        "38 84 dd 4e c7 b6 a5 39 a2 5f 35 db ac d1 dc ba " 
        "fa 67 4f 3b 9e 72 "; */
    const char *captured_cmd = 
        "80 02 00 00 00 f6 00 00 01 57 80 00 00 00 00 00 "
        "00 0c 40 00 00 09 00 00 00 00 03 73 74 6f 00 7e "
        "00 20 8d 3e 4b 9e 00 26 dc ba 28 3f 49 98 eb 18 "
        "50 3a d5 8c 3a ac a3 a8 4e 65 80 e9 c6 d2 ba a1 "
        "51 fd 00 10 4f d7 2b 64 cb 5e 5c 2d 25 81 20 61 "
        "05 c4 ae 14 be 98 2e 24 9d 6d c9 8c c2 b5 5f b8 "
        "2a 6c 9f f1 5d b1 6f 05 1d 13 53 98 6a 89 04 56 "
        "a5 44 e1 47 e6 ee 58 00 38 24 4d 48 83 8e ac 1e "
        "16 54 27 1e 17 2b 09 6b 13 1e 88 7e 2f d4 84 ee "
        "55 98 4e df 8d 83 fa 63 ce 0c 82 f9 0a 4e 00 56 "
        "00 23 00 12 00 04 04 72 00 00 00 10 00 10 00 20 "
        "00 10 00 20 b6 d0 d1 fe 3b 99 35 b8 d2 5b 21 18 "
        "31 02 a8 70 b8 c9 c4 22 52 b1 cc b3 7a b7 e0 13 "
        "32 5f f0 7a 00 20 37 3f e8 db d2 eb 13 5a 55 6a "
        "e7 a8 d5 90 56 90 c8 46 3e 71 c9 4c 92 3c 31 c6 "
        "ff eb db 69 7c 6d "; 

    RunRawHexCmd(ctx, captured_cmd, "Replay Captured Load");
}

void Test_Replay_Capture_Sign(TpmTestContext *ctx) {
    // ./sign -hk 80000001 -halg sm3 -salg sm2 -if policies/aaa -os sig.bin -pwdk sig 
    const char *captured_cmd = 
        "80 02 00 00 00 4c 00 00 01 5d 80 00 00 01 00 00 "
        "00 0c 40 00 00 09 00 00 00 00 03 73 69 67 00 20 "
        "8d 83 c7 af 17 f5 44 df fb 98 9f 53 cd 6a af dc "
        "2e da 6c a5 ea 7f ef 3d d7 b2 f0 ee 82 30 66 0d "
        "00 1b 00 12 80 24 40 00 00 07 00 00 ";
        
    RunRawHexCmd(ctx, captured_cmd, "Replay Captured Sign");
}

void Test_Replay_Capture_Verifysignature(TpmTestContext *ctx) {
    // ./verifysignature -hk 80000001 -halg sm3 -ecc -if policies/aaa -is sig.bin 
    const char *captured_cmd = 
        "80 01 00 00 00 78 00 00 01 77 80 00 00 01 00 20 "
        "8d 83 c7 af 17 f5 44 df fb 98 9f 53 cd 6a af dc "
        "2e da 6c a5 ea 7f ef 3d d7 b2 f0 ee 82 30 66 0d "
        "00 1b 00 12 00 20 49 24 5f 34 ec 66 ab eb ba f4 "
        "ed ec b5 41 ea 73 22 49 ec c5 58 06 99 4d 47 1a "
        "ab bb a8 d8 5f c5 00 20 6e c1 24 9c 41 72 54 5d "
        "4a 60 db 00 5b 3b dd b3 d7 63 79 65 fa 24 07 dd "
        "d5 3f 5e 4b c2 27 98 41";
        
    RunRawHexCmd(ctx, captured_cmd, "Replay Captured verifysignature");
}
//  80 01 00 00 00 0e 00 00 01 65 80 00 00 01 

void Test_Replay_Capture_Flushcontext(TpmTestContext *ctx) {
    // ./flushcontext -ha 80000001
    const char *captured_cmd = 
        "80 01 00 00 00 0e 00 00 01 65 80 00 00 01 ";
        
    RunRawHexCmd(ctx, captured_cmd, "Replay Captured flushcontext 80000001");

    // ./flushcontext -ha 80000000
    const char *captured_cmd2 = 
        "80 01 00 00 00 0e 00 00 01 65 80 00 00 00 ";
        
    RunRawHexCmd(ctx, captured_cmd2, "Replay Captured flushcontext 80000000");
}


/* =========================================================================
 * Main Task Entry
 * ========================================================================= */
void TPMTestTask(void *arg) {
    (void)arg;
    
    // Static allocation to avoid stack overflow on small task stacks
    static TpmTestContext ctx;

    // 1. Initialization
    _plat__Signal_PowerOn();
    _plat__SetNvAvail();
    _plat__Signal_Reset();
    _plat__NVEnable(NULL, 0);

    // 2. Manufacture (One-time logic)
    if (_plat__NVNeedsManufacture()) {
        printf("[TPM] Manufacturing...\n");
        if (TPM_Manufacture(1) == 0) {
            printf("[TPM] Done. Resetting.\n");
            TPM_TearDown();
            _plat__Signal_PowerOn();
            _plat__NVEnable(NULL, 0);
            _plat__Signal_Reset();
        } else {
            printf("[TPM] Manufacture Failed!\n");
            return;
        }
    }

    printf("=== TPM Modular Test Suite Started ===\n");

    // Execute Modules
    Test_Startup(&ctx);
    LOS_TaskDelay(2);
    
    /* Test_SelfTest(&ctx);
    LOS_TaskDelay(2);
    
    Test_GetRandom(&ctx);
    LOS_TaskDelay(2);
    
    Test_PCR_Read(&ctx);
    LOS_TaskDelay(2);
    
    Test_GetCapability(&ctx);
    LOS_TaskDelay(2);
    
    Test_Hash(&ctx);
    LOS_TaskDelay(2);
    
    Test_NV_Storage(&ctx);
    LOS_TaskDelay(2);
    
    Test_SM2_Hierarchy(&ctx); */
    
    Test_Replay_Capture_CreatePrimary(&ctx);
    Test_Replay_Capture_Create(&ctx);
    Test_Replay_Capture_Load(&ctx);
    Test_Replay_Capture_Sign(&ctx);
    Test_Replay_Capture_Verifysignature(&ctx);
    Test_Replay_Capture_Flushcontext(&ctx);
    LOS_TaskDelay(2);

    printf("\n=== All Tests Finished ===\n");
}

/* App Entry */
void TPMTestApp(void) {
    unsigned int ret;
    unsigned int taskID;
    TSK_INIT_PARAM_S task = { 0 };

    task.pfnTaskEntry = (TSK_ENTRY_FUNC)TPMTestTask;
    task.uwStackSize  = TASK_STACK_SIZE;
    task.pcName       = "TPMTestTask";
    task.usTaskPrio   = TASK_PRI;

    ret = LOS_TaskCreate(&taskID, &task);
    if (ret != LOS_OK) {
        printf("TPMTestTask create failed: 0x%X\n", ret);
    }
}