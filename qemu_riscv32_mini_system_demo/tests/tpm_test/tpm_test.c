/*
 * TPM 2.0 Modular Test Suite
 * Protocol: Big-Endian (Network Byte Order) required for all TPM commands.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

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
#define TPM_ALG_SM3_256          0x0012
#define TPM_ALG_RSASSA           0x0014
#define TPM_ALG_AES_128_CFB      0x0043  /* note: mode encoding may vary; here for human clarity */
#define TPM_ALG_KDF1_SP800_56A   0x0020  /* common KDF; alternative: 0x0022 KDF_CTR_HMAC_SHA256 */


// Context to manage buffers across modules
typedef struct {
    uint8_t cmd_buf[512];
    uint8_t rsp_buf[2048];
    uint8_t *rsp_ptr;
    uint32_t rsp_size;
} TpmTestContext;

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
    write_be16(p, TPM_ALG_SHA256); p += 2;
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
    write_be32(ctx->cmd_buf + off, 22); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_CC_GetCapability); off += 4;
    
    write_be32(ctx->cmd_buf + off, TPM_CAP_TPM_PROPERTIES); off += 4;
    write_be32(ctx->cmd_buf + off, TPM_PT_FIXED); off += 4;
    write_be32(ctx->cmd_buf + off, 1); off += 4;

    if (TpmSendCmd(ctx, off, "Sending GetCap") == TPM_RC_SUCCESS) {
        // Skip header(10), more(1), cap(4), count(4) to get to property
        // uint32_t prop_val = read_be32(ctx->rsp_ptr + 10 + 1 + 4 + 4 + 4); 
        // printf("TPM_PT_FIXED Value: 0x%08X\n", prop_val);
        // printf("✓ Capability OK\n");
        parse_GetCapability(ctx->rsp_ptr, ctx->rsp_size);
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
    write_be16(ctx->cmd_buf + off, TPM_ALG_SHA256); off += 2;
    write_be32(ctx->cmd_buf + off, 0x40000001); off += 4; // Owner
    
    write_be32(ctx->cmd_buf + size_off, off);

    if (TpmSendCmd(ctx, off, "Sending Hash") == TPM_RC_SUCCESS) {
        // Header(10) + Size(2) + Digest
        uint16_t d_size = read_be16(ctx->rsp_ptr + 10);
        printf("Hash Size: %u\n", d_size);
        const uint8_t expected[] = {
            0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2, 0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6, 0x86, 0xcf,
            0x0c, 0x3f, 0x5d, 0x5a, 0x86, 0xaf, 0xf3, 0xca, 0x12, 0x02, 0x0c, 0x92, 0x3a, 0xdc, 0x6c, 0x92
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
        write_be16(ctx->cmd_buf + off, TPM_ALG_SHA256); off += 2;
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

void Test_ECC_Crypto(TpmTestContext *ctx) {
    printf("\n--- Test 8: ECC Crypto (NIST P-256) ---\n");
    uint32_t key_handle = 0;

    // 1. CreatePrimary
    {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_CreatePrimary); off += 4;
        write_be32(ctx->cmd_buf + off, 0x40000001); off += 4;
        off += write_password_session(ctx->cmd_buf + off);
        
        // Sensitive
        write_be16(ctx->cmd_buf + off, 4); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        
        // Public
        uint32_t pub_size_off = off; off += 2;
        uint32_t pub_start = off;
        write_be16(ctx->cmd_buf + off, 0x0023); off += 2; // ECC
        write_be16(ctx->cmd_buf + off, TPM_ALG_SHA256); off += 2;
        write_be32(ctx->cmd_buf + off, 0x00040072); off += 4; // Sign|Fixed|SensitiveDataOrigin
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        
        // ECC Params
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; // Null Sym
        write_be16(ctx->cmd_buf + off, 0x0018); off += 2; // ECDSA
        write_be16(ctx->cmd_buf + off, 0x0003); off += 2; // NIST_P256
        write_be16(ctx->cmd_buf + off, 0x0000); off += 2; // Null KDF
        write_be16(ctx->cmd_buf + off, 0); off += 2; // Unique
        
        write_be16(ctx->cmd_buf + pub_size_off, off - pub_start);
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be32(ctx->cmd_buf + off, 0); off += 4;
        
        write_be32(ctx->cmd_buf + size_off, off);
        
        if (TpmSendCmd(ctx, off, "CreatePrimary ECC") == TPM_RC_SUCCESS) {
            key_handle = read_be32(ctx->rsp_ptr + 14);
            printf("✓ Handle: 0x%08X\n", key_handle);
        } else {
            return;
        }
    }
    
    // 2. Sign
    if (key_handle) {
        uint8_t digest[32];
        memset(digest, 0xAA, 32); // Mock hash
        
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_SESSIONS); off += 2;
        uint32_t size_off = off; off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_Sign); off += 4;
        write_be32(ctx->cmd_buf + off, key_handle); off += 4;
        off += write_password_session(ctx->cmd_buf + off);
        
        write_be16(ctx->cmd_buf + off, 32); off += 2;
        memcpy(ctx->cmd_buf + off, digest, 32); off += 32;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        
        // Validation (Null Ticket)
        write_be16(ctx->cmd_buf + off, 0x8004); off += 2;
        write_be32(ctx->cmd_buf + off, 0x40000007); off += 4;
        write_be16(ctx->cmd_buf + off, 0); off += 2;
        
        write_be32(ctx->cmd_buf + size_off, off);
        
        if (TpmSendCmd(ctx, off, "Sign ECC") == TPM_RC_SUCCESS) {
            printf("✓ ECC Signature Generated.\n");
        }
    }
    
    // 3. Flush
    if (key_handle) {
        uint32_t off = 0;
        write_be16(ctx->cmd_buf + off, TPM_ST_NO_SESSIONS); off += 2;
        write_be32(ctx->cmd_buf + off, 10 + 4); off += 4;
        write_be32(ctx->cmd_buf + off, TPM_CC_FlushContext); off += 4;
        write_be32(ctx->cmd_buf + off, key_handle); off += 4;
        _plat__RunCommand(off, ctx->cmd_buf, &ctx->rsp_size, &ctx->rsp_ptr);
    }
}

/* =========================================================================
 * RSA SRK -> Create RSA child -> Load -> Sign/Decrypt workflow
 *
 * High level:
 *  1) CreatePrimary(parent=Owner)  --- create RSA SRK (restricted/decrypt)
 *  2) Create (parent=SRK)          --- create an RSA child (sign/decrypt)
 *  3) Load   (parent=SRK)          --- load child private/public -> object handle
 *  4) Sign (or Decrypt) using child handle
 *
 * All wire fields are BIG-ENDIAN. Sizes follow TPM2.0 wire format.
 * ========================================================================= */


/* Utility: extract TPM2B (size-prefixed) pointer and length.
   Returns pointer to data content (after size field), sets out_len to length,
   sets *next_off to offset after this TPM2B (relative to base pointer).
   Assumes size field is BE16.
*/
static const uint8_t* parse_TPM2B(const uint8_t *base, uint32_t base_size, uint32_t off, uint16_t *out_len, uint32_t *next_off)
{
    if (off + 2 > base_size) return NULL;
    uint16_t sz = read_be16(base + off);
    if (off + 2 + sz > base_size) return NULL;
    if (out_len) *out_len = sz;
    if (next_off) *next_off = off + 2 + sz;
    return base + off + 2;
}

/* Build and send CreatePrimary for RSA SRK.
   - ctx: context
   - out_handle: pointer to uint32_t to receive primary handle
   Returns: rc (BE uint32)
*/
static uint32_t CreatePrimary_RSA_SRK(TpmTestContext *ctx, uint32_t *out_handle)
{
    // We'll build a TPM2_CreatePrimary command with SESSIONS (password) area.
    // Template (TPMT_PUBLIC) fields:
    //   type = RSA (0x0001)
    //   nameAlg = SHA256
    //   objectAttributes = Restricted | Decrypt | FixedTPM | FixedParent | SensitiveDataOrigin | UserWithAuth
    //                      bits -> value commonly 0x00030072
    //   parameters.rsaDetail.symmetric = AES_128_CFB (0x0006) [if TPM rejects, set to TPM_ALG_NULL]
    //   parameters.rsaDetail.scheme = TPM_ALG_NULL
    //   parameters.rsaDetail.keyBits = 2048
    //   parameters.rsaDetail.exponent = 0 (default)
    //
    // Wire layout (after header/handles/authorization):
    //   TPM2B_SENSITIVE_CREATE (size + sensitive)
    //   TPM2B_PUBLIC (size + public)
    //   outsideInfo (TPM2B)
    //   PCR selection

    uint8_t *cmd = ctx->cmd_buf;
    uint8_t *rsp = ctx->rsp_buf;
    uint32_t c_off = 0;

    write_be16(cmd + c_off, TPM_ST_SESSIONS); c_off += 2;
    uint32_t size_off = c_off; c_off += 4;
    write_be32(cmd + c_off, TPM_CC_CreatePrimary); c_off += 4;

    // Parent handle (Owner)
    write_be32(cmd + c_off, 0x40000001); c_off += 4;

    // Auth area (password session - empty)
    c_off += write_password_session(cmd + c_off);

    /* TPM2B_SENSITIVE_CREATE
       struct:
         size (UINT16)
         sensitive: userAuth (TPM2B_AUTH) + data (TPM2B_DIGEST) - here leave empty userAuth/data
    */
    uint32_t sens_start = c_off;
    c_off += 2; // placeholder for TPM2B_SENSITIVE_CREATE.size (UINT16 BE)

    // userAuth (TPM2B_AUTH) - empty
    write_be16(cmd + c_off, 0); c_off += 2;
    // data (TPM2B_DIGEST) - empty
    write_be16(cmd + c_off, 0); c_off += 2;

    uint16_t sens_size = (uint16_t)(c_off - (sens_start + 2));
    write_be16(cmd + sens_start, sens_size);

    /* TPM2B_PUBLIC */
    uint32_t pub_start = c_off;
    c_off += 2; // TPM2B_PUBLIC.size placeholder (UINT16)

    // TPMS_PUBLIC area:
    // type (UINT16)
    write_be16(cmd + c_off, TPM_ALG_RSA); c_off += 2;
    // nameAlg
    write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2;
    // objectAttributes (UINT32)
    write_be32(cmd + c_off, 0x00030072); c_off += 4; // FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|Restricted|Decrypt
    // authPolicy (TPM2B_DIGEST) - empty
    write_be16(cmd + c_off, 0); c_off += 2;

    // parameters: RSA signing key
    write_be16(cmd + c_off, TPM_ALG_NULL);  c_off += 2;   // symmetric = NULL
    // scheme = RSASSA
    write_be16(cmd + c_off, 0x0014); c_off += 2;  // scheme TPM_ALG_RSASSA
    write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2;  // hashAlg for RSASSA
    // keyBits(UINT16)
    write_be16(cmd + c_off, 2048); c_off += 2;
    // exponent(UINT32)
    write_be32(cmd + c_off, 0); c_off += 4;
    // unique (TPM2B_PUBLIC_KEY_RSA) -> size (UINT16) + buffer (empty)
    write_be16(cmd + c_off, 0); c_off += 2;

    // Fill TPM2B_PUBLIC.size
    uint16_t pub_size = (uint16_t)(c_off - (pub_start + 2));
    write_be16(cmd + pub_start, pub_size);

    // outsideInfo (TPM2B) empty
    write_be16(cmd + c_off, 0); c_off += 2;

    // PCR selection: count 0
    write_be32(cmd + c_off, 0); c_off += 4;

    // finalize size
    write_be32(cmd + size_off, c_off);

    // send
    ctx->rsp_size = sizeof(ctx->rsp_buf);
    ctx->rsp_ptr = ctx->rsp_buf;
    memset(ctx->rsp_buf, 0, ctx->rsp_size);
    _plat__RunCommand(c_off, cmd, &ctx->rsp_size, (unsigned char**)&ctx->rsp_ptr);

    if (!ctx->rsp_ptr || ctx->rsp_size < 10) return 0xFFFFFFFF;
    uint32_t rc = read_be32(ctx->rsp_ptr + 6);
    if (rc != TPM_RC_SUCCESS) {
        printf("CreatePrimary (SRK) failed: 0x%08X\n", rc);
        // If rc indicates algorithm/kdf not supported, try switching symmetric->TPM_ALG_NULL.
        return rc;
    }

    // Parse handle: response with tag 0x8002 (SESSIONS): header(10) + paramSize(4) + handle(4) ...
    uint32_t handle = read_be32(ctx->rsp_ptr + 14);
    if (out_handle) *out_handle = handle;
    printf("CreatePrimary SRK succeeded. Handle=0x%08X\n", handle);
    return rc;
}

/* Create an RSA child under parent (SRK).
   It sends TPM2_Create (parentHandle) with a public template for an RSA signing key
   Returns rc. On success it stores outPrivate and outPublic into ctx->scratch buffers:
     - priv_ptr and priv_len (TPM2B_PRIVATE)
     - pub_ptr and pub_len  (TPM2B_PUBLIC)
   For simplicity we put them into ctx->rsp_buf copies (caller may copy out if needed).
*/
static uint32_t Create_RSA_Child_SaveInCtx(TpmTestContext *ctx, uint32_t parentHandle,
                                           uint8_t **out_priv_ptr, uint32_t *out_priv_len,
                                           uint8_t **out_pub_ptr, uint32_t *out_pub_len)
{
    uint8_t *cmd = ctx->cmd_buf;
    uint32_t c_off = 0;
    write_be16(cmd + c_off, TPM_ST_SESSIONS); c_off += 2;
    uint32_t size_off = c_off; c_off += 4;
    write_be32(cmd + c_off, TPM_CC_Create); c_off += 4;

    // parentHandle
    write_be32(cmd + c_off, parentHandle); c_off += 4;

    // Auth area (password session)
    c_off += write_password_session(cmd + c_off);

    // InSensitive (TPM2B_SENSITIVE_CREATE)
    uint32_t sens_start = c_off; c_off += 2;
    // userAuth (TPM2B) empty
    write_be16(cmd + c_off, 0); c_off += 2;
    // data (TPM2B) empty
    write_be16(cmd + c_off, 0); c_off += 2;
    // fill size
    write_be16(cmd + sens_start, (uint16_t)(c_off - (sens_start + 2)));

    // InPublic (TPM2B_PUBLIC) - RSA signing key (non-restricted, sign)
    uint32_t pub_start = c_off; c_off += 2;
    // type, nameAlg
    write_be16(cmd + c_off, TPM_ALG_RSA); c_off += 2;
    write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2;
    // attributes: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|Sign
    write_be32(cmd + c_off, 0x00040072); c_off += 4;
    // authPolicy empty
    write_be16(cmd + c_off, 0); c_off += 2;
    // FIX: Specify RSASSA scheme for a Sign key (TPM2.0 Spec Part 3, 20.3.3)
    // symmetric null (Correct for non-restricted key)
    write_be16(cmd + c_off, TPM_ALG_NULL); c_off += 2; 
    // scheme (TPMT_RSA_SCHEME)
    write_be16(cmd + c_off, TPM_ALG_RSASSA); c_off += 2; // scheme = RSASSA (0x0014)
    write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2; // hashAlg = SHA256 (0x000B)
    // keyBits
    write_be16(cmd + c_off, 2048); c_off += 2; 
    // exponent
    write_be32(cmd + c_off, 0); c_off += 4;
    // unique (TPM2B_PUBLIC_KEY_RSA) empty
    write_be16(cmd + c_off, 0); c_off += 2;

    // fill public size
    write_be16(cmd + pub_start, (uint16_t)(c_off - (pub_start + 2)));

    // outsideInfo (TPM2B) empty
    write_be16(cmd + c_off, 0); c_off += 2;
    // PCR selection empty
    write_be32(cmd + c_off, 0); c_off += 4;

    write_be32(cmd + size_off, c_off);

    // send
    ctx->rsp_size = sizeof(ctx->rsp_buf);
    ctx->rsp_ptr = ctx->rsp_buf;
    memset(ctx->rsp_buf, 0, ctx->rsp_size);
    _plat__RunCommand(c_off, cmd, &ctx->rsp_size, (unsigned char**)&ctx->rsp_ptr);

    if (!ctx->rsp_ptr || ctx->rsp_size < 10) return 0xFFFFFFFF;
    uint32_t rc = read_be32(ctx->rsp_ptr + 6);
    if (rc != TPM_RC_SUCCESS) {
        printf("Create (child) failed: 0x%08X\n", rc);
        return rc;
    }

    // Parse response: tag 0x8002 => header(10) + paramSize(4) + outPrivate(TPM2B_PRIVATE) + outPublic(TPM2B_PUBLIC) ...
    // Locate outPrivate at offset = 14
    uint32_t off = 14;
    uint16_t priv_sz = 0;
    const uint8_t *priv_ptr = parse_TPM2B(ctx->rsp_ptr, ctx->rsp_size, off, &priv_sz, &off);
    if (!priv_ptr) {
        printf("Create: cannot parse outPrivate\n");
        return 0xFFFFFFFF;
    }
    // outPublic next
    uint16_t pub_sz = 0;
    const uint8_t *pub_ptr = parse_TPM2B(ctx->rsp_ptr, ctx->rsp_size, off, &pub_sz, &off);
    if (!pub_ptr) {
        printf("Create: cannot parse outPublic\n");
        return 0xFFFFFFFF;
    }

    // copy to dynamically allocated buffers (caller owns them)
    if (out_priv_ptr && out_priv_len) {
        uint8_t *p = malloc(priv_sz);
        if (p) { memcpy(p, priv_ptr, priv_sz); *out_priv_ptr = p; *out_priv_len = priv_sz; }
    }
    if (out_pub_ptr && out_pub_len) {
        uint8_t *p = malloc(pub_sz);
        if (p) { memcpy(p, pub_ptr, pub_sz); *out_pub_ptr = p; *out_pub_len = pub_sz; }
    }
    printf("Create(child) succeeded: priv=%u bytes pub=%u bytes\n", priv_sz, pub_sz);
    return rc;
}

/* Load child under parent. Takes parentHandle and TPM2B_PRIVATE/TPM2B_PUBLIC buffers (raw bytes
   as produced by Create). Returns object handle in out_handle.
*/
static uint32_t LoadChild(TpmTestContext *ctx, uint32_t parentHandle,
                          const uint8_t *priv_buf, uint32_t priv_len,
                          const uint8_t *pub_buf, uint32_t pub_len,
                          uint32_t *out_handle)
{
    uint8_t *cmd = ctx->cmd_buf;
    uint32_t c_off = 0;
    write_be16(cmd + c_off, TPM_ST_SESSIONS); c_off += 2;
    uint32_t size_off = c_off; c_off += 4;
    write_be32(cmd + c_off, TPM_CC_Load); c_off += 4;

    // parent handle
    write_be32(cmd + c_off, parentHandle); c_off += 4;

    // Auth area
    c_off += write_password_session(cmd + c_off);

    // inPrivate (TPM2B_PRIVATE) - needs leading uint16 size (BE) + buffer
    write_be16(cmd + c_off, (uint16_t)priv_len); c_off += 2;
    memcpy(cmd + c_off, priv_buf, priv_len); c_off += priv_len;

    // inPublic (TPM2B_PUBLIC)
    write_be16(cmd + c_off, (uint16_t)pub_len); c_off += 2;
    memcpy(cmd + c_off, pub_buf, pub_len); c_off += pub_len;

    write_be32(cmd + size_off, c_off);

    // send
    ctx->rsp_size = sizeof(ctx->rsp_buf);
    ctx->rsp_ptr = ctx->rsp_buf;
    memset(ctx->rsp_buf, 0, ctx->rsp_size);
    _plat__RunCommand(c_off, cmd, &ctx->rsp_size, (unsigned char**)&ctx->rsp_ptr);
    if (!ctx->rsp_ptr || ctx->rsp_size < 18) return 0xFFFFFFFF;
    uint32_t rc = read_be32(ctx->rsp_ptr + 6);
    if (rc != TPM_RC_SUCCESS) {
        printf("Load failed: 0x%08X\n", rc);
        return rc;
    }
    // Response (SESSIONS): header(10)+paramSize(4)+objectHandle(4)+... so handle at offset 14
    uint32_t handle = read_be32(ctx->rsp_ptr + 14);
    if (out_handle) *out_handle = handle;
    printf("Load succeeded. ObjectHandle=0x%08X\n", handle);
    return rc;
}

/* Sign using RSA key handle (RSASSA-PKCS1v1_5 with SHA256 assumed).
   We construct TPM2_Sign request: digest (TPM2B_DIGEST) and scheme NULL to use key default.
*/
static uint32_t SignWithKey(TpmTestContext *ctx, uint32_t keyHandle, const uint8_t *digest32)
{
    uint8_t *cmd = ctx->cmd_buf;
    uint32_t c_off = 0;
    write_be16(cmd + c_off, TPM_ST_SESSIONS); c_off += 2;
    uint32_t size_off = c_off; c_off += 4;
    write_be32(cmd + c_off, TPM_CC_Sign); c_off += 4;

    write_be32(cmd + c_off, keyHandle); c_off += 4;

    // auth
    c_off += write_password_session(cmd + c_off);

    // digest (TPM2B_DIGEST)
    write_be16(cmd + c_off, 32); c_off += 2;
    memcpy(cmd + c_off, digest32, 32); c_off += 32;

    // inScheme - Null (use key default)
    write_be16(cmd + c_off, TPM_ALG_NULL); c_off += 2;
    write_be16(cmd + c_off, TPM_ALG_NULL); c_off += 2; // some TPMs expect scheme+hash

    // validation (TPMT_TK_HASHCHECK) - Null ticket (tag + hierarchy + size 0)
    write_be16(cmd + c_off, 0x8004); c_off += 2; // TPM_ST_HASHCHECK
    write_be32(cmd + c_off, 0x40000007); c_off += 4; // hierarchy: NULL
    write_be16(cmd + c_off, 0); c_off += 2; // digest size 0

    write_be32(cmd + size_off, c_off);

    ctx->rsp_size = sizeof(ctx->rsp_buf);
    ctx->rsp_ptr = ctx->rsp_buf;
    memset(ctx->rsp_buf, 0, ctx->rsp_size);
    _plat__RunCommand(c_off, cmd, &ctx->rsp_size, (unsigned char**)&ctx->rsp_ptr);
    if (!ctx->rsp_ptr || ctx->rsp_size < 10) return 0xFFFFFFFF;
    uint32_t rc = read_be32(ctx->rsp_ptr + 6);
    if (rc != TPM_RC_SUCCESS) {
        printf("Sign failed: 0x%08X\n", rc);
        return rc;
    }
    // parse signature: Response header(10)+paramSize(4)+TPMT_SIGNATURE ...
    // For RSA signature, TPMT_SIGNATURE: sigAlg(UINT16) + signature (TPM2B)...
    // We'll try to locate sigAlg at offset 14
    uint32_t off = 14;
    uint16_t sigAlg = read_be16(ctx->rsp_ptr + off);
    off += 2;
    uint16_t sigSize = read_be16(ctx->rsp_ptr + off); off += 2;
    printf("Sign succeeded. SigAlg=0x%04X sigSize=%u\n", sigAlg, sigSize);
    // signature bytes start at ctx->rsp_ptr + off
    print_hex("Signature", ctx->rsp_ptr + off, sigSize);
    return rc;
}

/* High-level workflow: create SRK, create RSA child, load & sign */
void Test_RSA_SRK_Workflow(TpmTestContext *ctx)
{
    uint32_t srk_handle = 0;
    uint32_t rc;

    printf("\n--- Test RSA SRK Workflow: CreatePrimary(SRK) -> Create -> Load -> Sign ---\n");

    // 1) CreatePrimary SRK
    rc = CreatePrimary_RSA_SRK(ctx, &srk_handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("CreatePrimary SRK failed 0x%08X - try changing symmetric->TPM_ALG_NULL or adjusting KDF\n", rc);
        return;
    }

    // 2) Create an RSA child under SRK
    uint8_t *priv = NULL, *pub = NULL; uint32_t priv_len = 0, pub_len = 0;
    rc = Create_RSA_Child_SaveInCtx(ctx, srk_handle, &priv, &priv_len, &pub, &pub_len);
    if (rc != TPM_RC_SUCCESS) {
        printf("Create child failed 0x%08X\n", rc);
        if (priv) free(priv);
        if (pub) free(pub);
        return;
    }

    // Debug: print sizes
    printf("Child created. priv_len=%u pub_len=%u\n", priv_len, pub_len);

    // 3) Load child
    uint32_t child_handle = 0;
    rc = LoadChild(ctx, srk_handle, priv, priv_len, pub, pub_len, &child_handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("Load child failed 0x%08X\n", rc);
        free(priv); free(pub);
        return;
    }

    // 4) Sign (mock digest)
    uint8_t digest[32] = {0};
    // for demo use: SHA256("hello") etc. Here we just pass zeros or you can pass real hash
    rc = SignWithKey(ctx, child_handle, digest);
    if (rc != TPM_RC_SUCCESS) {
        printf("SignWithKey returned 0x%08X\n", rc);
    }

    // 5) Flush the loaded child
    {
        uint8_t flushCmd[16];
        uint32_t off = 0;
        write_be16(flushCmd + off, TPM_ST_NO_SESSIONS); off += 2;
        write_be32(flushCmd + off, 12); off += 4; // 12 bytes length (2+4+4+2? but we place 12 + 4 bytes handle below)
        write_be32(flushCmd + off, TPM_CC_FlushContext); off += 4;
        write_be32(flushCmd + off, child_handle); off += 4;
        ctx->rsp_size = sizeof(ctx->rsp_buf);
        ctx->rsp_ptr = ctx->rsp_buf;
        _plat__RunCommand(off, flushCmd, &ctx->rsp_size, (unsigned char**)&ctx->rsp_ptr);
        printf("Child flushed.\n");
    }

    free(priv); free(pub);
    printf("=== RSA SRK Workflow Finished ===\n");
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
    
    Test_SelfTest(&ctx);
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
    
    // Test_ECC_Crypto(&ctx);
    Test_RSA_SRK_Workflow(&ctx);

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