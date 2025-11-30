/*
 * TPM 2.0 Basic Test Suite (Corrected for Big-Endian Protocol)
 * * Protocol Note: TPM 2.0 over the wire mandates Big-Endian (Network Byte Order)
 * for ALL integers (Tag, Size, CommandCode, and Parameters/Handles).
 *
 * Contains:
 * - TPM2_Startup (CLEAR/STATE)
 * - TPM2_GetCapability (TPM_PT_FIXED)
 * - TPM2_GetRandom (request 16 bytes)
 * - TPM2_PCR_Read (SHA256, PCR0)
 * - TPM2_SelfTest (full)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "ohos_init.h"
#include "cmsis_os2.h"
#include "los_task.h"

// #include "prototypes/Manufacture_fp.h"

#define TASK_STACK_SIZE      0x4000 
#define TASK_PRI             16

/* TPM constants (Standard values) */
#define TPM_ST_NO_SESSIONS       0x8001
#define TPM_ST_SESSIONS          0x8002
#define TPM_CC_Startup           0x00000144
#define TPM_CC_GetCapability     0x0000017A
#define TPM_CC_GetRandom         0x0000017B
#define TPM_CC_PCR_Read          0x0000017E
#define TPM_CC_SelfTest          0x00000143

#define TPM_SU_CLEAR             0x0000
#define TPM_SU_STATE             0x0001

#define TPM_CAP_TPM_PROPERTIES   0x00000006
#define TPM_PT_FIXED             0x00000100

#define TPM_ALG_SHA256           0x000B
#define TPM_ALG_SM3_256          0x0012

#define TPM_RC_SUCCESS           0x00000000
#define TPM_RC_INITIALIZE        0x00000100
#define TPM_RC_FAILURE           0x00000101

#define TPM_RS_PW                0x40000009

/* Utility printing */
void print_hex(const char *label, const uint8_t *data, uint32_t size)
{
    printf("%s (%u bytes):\n", label, size);
    if (!data || size == 0) {
        printf("(empty)\n");
        return;
    }
    for (uint32_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

const char* get_tpm_rc_name(uint32_t rc)
{
    switch(rc) {
        case TPM_RC_SUCCESS: return "TPM_RC_SUCCESS";
        case TPM_RC_INITIALIZE: return "TPM_RC_INITIALIZE";
        case 0x00000095: return "TPM_RC_UNMARSHAL (Format Error)"; // Typical for GetRandom size error
        case 0x000001D5: return "TPM_RC_SIZE (Parameter 1)";
        case 0x000001C4: return "TPM_RC_VALUE (Parameter 1)";
        default: return "TPM_RC_ERROR";
    }
}

/* =========================================================================
 * Endianness Helpers (TPM 2.0 IS ALWAYS BIG-ENDIAN ON WIRE)
 * ========================================================================= */

static inline void write_be16(uint8_t *buf, uint16_t v)
{
    buf[0] = (uint8_t)((v >> 8) & 0xFF);
    buf[1] = (uint8_t)(v & 0xFF);
}

static inline void write_be32(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)((v >> 24) & 0xFF);
    buf[1] = (uint8_t)((v >> 16) & 0xFF);
    buf[2] = (uint8_t)((v >> 8) & 0xFF);
    buf[3] = (uint8_t)(v & 0xFF);
}

static inline uint16_t read_be16(const uint8_t *buf)
{
    return (uint16_t)buf[1] | ((uint16_t)buf[0] << 8);
}

static inline uint32_t read_be32(const uint8_t *buf)
{
    return (uint32_t)buf[3] |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[0] << 24);
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

/* Helper to inject a Password Session (Empty Auth) into the command buffer */
/* Returns the number of bytes written */
static uint32_t write_password_session(uint8_t *buf)
{
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

/* Forward declarations */
extern void _TPM_Init(void);
extern void _plat__RunCommand(uint32_t size, unsigned char *command, uint32_t *response_size, unsigned char **response);
// extern int TPM_Manufacture(int firstTime); // Assuming this exists based on your log
// extern void _plat__Signal_PowerOn(void);
// extern void _plat__Signal_Reset(void);
// extern void _plat__SetNvAvail(void);
// extern void _plat__NVEnable(void *platParameter, uint32_t size);
// extern bool _plat__NVNeedsManufacture(void);

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

static void parse_GetRandom(const uint8_t *rsp_ptr, uint32_t rsp_size)
{
    uint16_t tag; uint32_t size; uint32_t rc;
    if (parse_tpm_resp_header(rsp_ptr, rsp_size, &tag, &size, &rc) != 0) return;

    printf("GetRandom RC = 0x%08X (%s)\n", rc, get_tpm_rc_name(rc));
    if (rc != TPM_RC_SUCCESS) return;

    // Payload starts at offset 10
    // Structure: size (UINT16 BE) + buffer
    if (rsp_size < 12) {
        printf("GetRandom: response too small\n");
        return;
    }

    /* FIX: Read size as BE16 */
    uint16_t rnd_size = read_be16(rsp_ptr + 10);
    printf("GetRandom: random size reported = %u\n", rnd_size);

    if ((uint32_t)rnd_size + 12 > rsp_size) {
        printf("GetRandom: truncated payload\n");
        return;
    }

    print_hex("GetRandom bytes", rsp_ptr + 12, rnd_size);

    // [VALIDATION] Check for all zeros (indicates underlying crypto failure)
    int all_zeros = 1;
    for (uint32_t i = 0; i < rnd_size; i++) {
        if (rsp_ptr[12 + i] != 0x00) {
            all_zeros = 0;
            break;
        }
    }
    if (all_zeros) {
        printf("!!! WARNING: GetRandom returned all zeros! OpenHiTLS BN_Mul logic may be broken.\n");
    } else {
        printf("✓ GetRandom data looks valid (entropy detected).\n");
    }
}

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

/* =========================================================================
 * Main Test Task
 * ========================================================================= */
void TPMTestTask(void *arg)
{
    (void)arg;
    uint8_t rsp_buf[2048];
    uint8_t *rsp_ptr = rsp_buf;
    uint32_t rsp_size;

    // 1. Power up Sequence
    _plat__Signal_PowerOn();
    _plat__SetNvAvail();
    _plat__Signal_Reset();
    _plat__NVEnable(NULL, 0);

    // 2. Manufacture Check
    bool manufacture = _plat__NVNeedsManufacture();
    if (manufacture)
    {
        printf("[TPM] NV requires manufacturing...\n");
        if (TPM_Manufacture(1) != 0)
        {
            printf("[TPM] Manufacture failed\n");
            return;
        }
        printf("[TPM] Manufacture completed successfully.\n");
        // Reset after manufacture to ensure clean state
        TPM_TearDown();
        _plat__Signal_PowerOn();
        _plat__NVEnable(NULL, 0);
        _plat__Signal_Reset();
    }

    printf("=== TPM Test Start (All Commands Big-Endian) ===\n");

    /* -------- Test 1: TPM2_Startup (CLEAR) ---------- */
    printf("\n--- Test 1: TPM2_Startup (CLEAR) ---\n");
    {
        uint8_t cmd[12];
        write_be16(cmd + 0, TPM_ST_NO_SESSIONS);
        write_be32(cmd + 2, 12);
        write_be32(cmd + 6, TPM_CC_Startup);
        write_be16(cmd + 10, TPM_SU_CLEAR); // Param: BE
        
        print_hex("Sending Startup(CLEAR)", cmd, sizeof(cmd));
        rsp_size = sizeof(rsp_buf);
        rsp_ptr = rsp_buf; memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(sizeof(cmd), cmd, &rsp_size, (unsigned char**)&rsp_ptr);

        if (rsp_ptr && rsp_size >= 10) {
            uint32_t rc = read_be32(rsp_ptr + 6);
            printf("Startup(CLEAR) response code: 0x%08X (%s)\n", rc, get_tpm_rc_name(rc));
            if (rc == TPM_RC_SUCCESS) printf("✓ Startup(CLEAR) successful\n");
        }
    }

    LOS_TaskDelay(2);

    /* -------- Test 2: TPM2_SelfTest (full) ---------- */
    printf("\n--- Test 2: TPM2_SelfTest (full) ---\n");
    {
        uint8_t cmd[11];
        write_be16(cmd + 0, TPM_ST_NO_SESSIONS);
        write_be32(cmd + 2, 11);
        write_be32(cmd + 6, TPM_CC_SelfTest);
        cmd[10] = 0x01; // fullTest (byte)
        
        print_hex("Sending SelfTest(full)", cmd, sizeof(cmd));
        rsp_size = sizeof(rsp_buf);
        rsp_ptr = rsp_buf; memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(sizeof(cmd), cmd, &rsp_size, (unsigned char**)&rsp_ptr);
        
        if (rsp_ptr) parse_SelfTest(rsp_ptr, rsp_size);
    }

    LOS_TaskDelay(2);

    /* -------- Test 3: TPM2_GetRandom (16 bytes) ---------- */
    printf("\n--- Test 3: TPM2_GetRandom (16 bytes) ---\n");
    {
        /* FIX: Command size is 12 bytes, Parameter is UINT16 */
        uint8_t cmd[12];
        write_be16(cmd + 0, TPM_ST_NO_SESSIONS);
        write_be32(cmd + 2, 12);
        write_be32(cmd + 6, TPM_CC_GetRandom);
        write_be16(cmd + 10, 16); // bytesRequested: UINT16 BE

        print_hex("Sending GetRandom", cmd, sizeof(cmd));
        rsp_size = sizeof(rsp_buf);
        rsp_ptr = rsp_buf; memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(sizeof(cmd), cmd, &rsp_size, (unsigned char**)&rsp_ptr);

        if (rsp_ptr) parse_GetRandom(rsp_ptr, rsp_size);
    }

    LOS_TaskDelay(2);

    /* -------- Test 4: TPM2_PCR_Read (SHA256, PCR0) ---------- */
    printf("\n--- Test 4: TPM2_PCR_Read (SHA256, PCR0) ---\n");
    {
        uint8_t cmd[20];
        write_be16(cmd + 0, TPM_ST_NO_SESSIONS);
        write_be32(cmd + 2, 20);
        write_be32(cmd + 6, TPM_CC_PCR_Read);

        /* Param Area: All BE */
        uint8_t *p = cmd + 10;
        write_be32(p, 1); p += 4;              /* pcrSelectionCount = 1 (BE) */
        write_be16(p, TPM_ALG_SHA256); p += 2; /* hashAlg (BE) */
        *p++ = 3;                              /* sizeOfSelect (byte) */
        *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; /* pcrSelect (bitmap) */

        rsp_size = sizeof(rsp_buf);
        rsp_ptr = rsp_buf; memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(sizeof(cmd), cmd, &rsp_size, (unsigned char**)&rsp_ptr);

        if (rsp_ptr) parse_PCR_Read(rsp_ptr, rsp_size);
    }

    LOS_TaskDelay(2);

    /* -------- Test 5: TPM2_GetCapability (TPM_PT_FIXED) ---------- */
    printf("\n--- Test 5: TPM2_GetCapability (TPM_PROPERTIES -> TPM_PT_FIXED) ---\n");
    {
        uint8_t cmd[22];
        write_be16(cmd + 0, TPM_ST_NO_SESSIONS);
        write_be32(cmd + 2, 22);
        write_be32(cmd + 6, TPM_CC_GetCapability);

        /* Param Area: All BE */
        uint8_t *p = cmd + 10;
        write_be32(p, TPM_CAP_TPM_PROPERTIES); p += 4;
        write_be32(p, TPM_PT_FIXED); p += 4;
        write_be32(p, 1); /* propertyCount (BE) */ p += 4;

        rsp_size = sizeof(rsp_buf);
        rsp_ptr = rsp_buf; memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(sizeof(cmd), cmd, &rsp_size, (unsigned char**)&rsp_ptr);

        if (rsp_ptr) parse_GetCapability(rsp_ptr, rsp_size);
    }

    LOS_TaskDelay(5);

    /* =========================================================================
     * Test 6: TPM2_Hash (SHA256)
     * ========================================================================= */
    printf("\n--- Test 6: TPM2_Hash (SHA256) ---\n");
    {
        const char *input_str = "123456";
        uint32_t input_len = 6;
        
        uint8_t cmd[64]; 
        uint32_t c_off = 0;
        
        // Header (NO SESSIONS is fine for Hash)
        write_be16(cmd + c_off, TPM_ST_NO_SESSIONS); c_off += 2;
        uint32_t size_offset = c_off; c_off += 4;
        write_be32(cmd + c_off, 0x0000017D); c_off += 4; // TPM_CC_Hash

        // Parameters
        // 1. Data (TPM2B_MAX_BUFFER)
        write_be16(cmd + c_off, input_len); c_off += 2;
        memcpy(cmd + c_off, input_str, input_len); c_off += input_len;

        // 2. HashAlg (TPMI_ALG_HASH) -> SHA256
        write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2;

        // 3. Hierarchy -> Owner
        write_be32(cmd + c_off, 0x40000001); c_off += 4;

        write_be32(cmd + size_offset, c_off);

        print_hex("Sending Hash", cmd, c_off);
        rsp_size = sizeof(rsp_buf);
        rsp_ptr = rsp_buf; memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);

        if (rsp_ptr) {
            uint32_t rc = read_be32(rsp_ptr + 6);
            if (rc == TPM_RC_SUCCESS) {
                // Parse TPM2B_DIGEST
                // Response (NO_SESSIONS): Tag(2)+Size(4)+RC(4) + DigestSize(2) + Digest
                // FIX: Do NOT skip 4 bytes for ParameterSize here because Tag is 8001
                uint32_t off = 10;
                
                uint16_t d_size = read_be16(rsp_ptr + off); off += 2;
                printf("Hash Size: %d\n", d_size);
                
                // Expected SHA256 of "123456"
                const uint8_t expected[] = {
                    0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2, 0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6, 0x86, 0xcf,
                    0x0c, 0x3f, 0x5d, 0x5a, 0x86, 0xaf, 0xf3, 0xca, 0x12, 0x02, 0x0c, 0x92, 0x3a, 0xdc, 0x6c, 0x92
                };
                /* const uint8_t expected[] = {
                    // 123456 --> 207CF410532F92A47DEE245CE9B11FF71F578EBD763EB3BBEA44EBD043D018FB
                    0x20, 0x7C, 0xF4, 0x10, 0x53, 0x2F, 0x92, 0xA4, 0x7D, 0xEE, 0x24, 0x5C, 0xE9, 0xB1, 0x1F, 0xF7,
                    0x1F, 0x57, 0x8E, 0xBD, 0x76, 0x3E, 0xB3, 0xBB, 0xEA, 0x44, 0xEB, 0xD0, 0x43, 0xD0, 0x18, 0xFB
                }; */
                print_hex("Expected Hash", expected, sizeof(expected));
                print_hex("Actual Hash", rsp_ptr + off, 32);
                compare_buffers("Hash Check", expected, rsp_ptr + off, 32);
            } else {
                printf("Hash Failed: 0x%08X\n", rc);
            }
        }
    }

    LOS_TaskDelay(5);

    /* =========================================================================
     * Test 7: NV Storage (Index 0x01500002) - WITH AUTH
     * ========================================================================= */
    printf("\n--- Test 7: NV Storage (Index 0x01500002) ---\n");
    uint32_t nv_index = 0x01500002;
    uint32_t nv_size = 8; 
    
    // Step 7.1: NV_DefineSpace (Requires Auth Session)
    {
        uint8_t cmd[256]; uint32_t c_off = 0;
        // FIX: Use TPM_ST_SESSIONS (0x8002)
        write_be16(cmd + c_off, 0x8002); c_off += 2; 
        uint32_t size_off = c_off; c_off += 4;
        write_be32(cmd + c_off, 0x0000012A); c_off += 4; // TPM_CC_NV_DefineSpace
        
        // Handles
        write_be32(cmd + c_off, 0x40000001); c_off += 4; // AuthHandle: Owner

        // FIX: Insert Authorization Area (Password Session)
        c_off += write_password_session(cmd + c_off);

        // Parameters
        // 1. Auth (TPM2B_AUTH)
        write_be16(cmd + c_off, 0); c_off += 2;

        // 2. PublicInfo (TPM2B_NV_PUBLIC)
        uint32_t pub_size_off = c_off; c_off += 2;
        uint32_t pub_start = c_off;
        
        write_be32(cmd + c_off, nv_index); c_off += 4; 
        write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2; 
        // Attr: OwnerWrite|OwnerRead|AuthRead|AuthWrite 0x00060006
        write_be32(cmd + c_off, 0x00060006); c_off += 4;
        write_be16(cmd + c_off, 0); c_off += 2; // Policy Size
        write_be16(cmd + c_off, nv_size); c_off += 2; // Data Size
        
        write_be16(cmd + pub_size_off, (c_off - pub_start));
        write_be32(cmd + size_off, c_off);

        printf("Sending NV_DefineSpace (With Auth)...\n");
        rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
        
        uint32_t rc = read_be32(rsp_ptr + 6);
        if (rc == 0x0000014B) { // TPM_RC_NV_DEFINED
            printf("NV Index already defined (OK)\n");
            rc = TPM_RC_SUCCESS;
        } else if (rc != TPM_RC_SUCCESS) {
            printf("NV_DefineSpace Failed: 0x%08X\n", rc);
        }
        
        if (rc == TPM_RC_SUCCESS) {
            // Step 7.2: NV_Write (Requires Auth)
            c_off = 0;
            write_be16(cmd + c_off, 0x8002); c_off += 2; // SESSIONS
            size_off = c_off; c_off += 4;
            write_be32(cmd + c_off, 0x00000137); c_off += 4; // TPM_CC_NV_Write
            
            write_be32(cmd + c_off, 0x40000001); c_off += 4; // Handle: Owner
            write_be32(cmd + c_off, nv_index);   c_off += 4; // Handle: Index

            // Auth Area
            c_off += write_password_session(cmd + c_off);

            // Parameters
            const uint8_t nv_data[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
            write_be16(cmd + c_off, 8); c_off += 2;
            memcpy(cmd + c_off, nv_data, 8); c_off += 8;
            write_be16(cmd + c_off, 0); c_off += 2; // Offset
            
            write_be32(cmd + size_off, c_off);
            
            printf("Sending NV_Write (With Auth)...\n");
            rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
            _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
            rc = read_be32(rsp_ptr + 6);
            
            if (rc == TPM_RC_SUCCESS) {
                 printf("✓ NV_Write Successful\n");

                 // Step 7.3: NV_Read (Requires Auth)
                 c_off = 0;
                 write_be16(cmd + c_off, 0x8002); c_off += 2; // SESSIONS
                 size_off = c_off; c_off += 4;
                 write_be32(cmd + c_off, 0x0000014E); c_off += 4; // TPM_CC_NV_Read
                 
                 write_be32(cmd + c_off, 0x40000001); c_off += 4; // Owner
                 write_be32(cmd + c_off, nv_index);   c_off += 4; // Index

                 // Auth Area
                 c_off += write_password_session(cmd + c_off);

                 // Params
                 write_be16(cmd + c_off, 8); c_off += 2; // Size
                 write_be16(cmd + c_off, 0); c_off += 2; // Offset
                 
                 write_be32(cmd + size_off, c_off);
                 
                 printf("Sending NV_Read (With Auth)...\n");
                 rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
                 _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
                 rc = read_be32(rsp_ptr + 6);
                 
                 if (rc == TPM_RC_SUCCESS) {
                     // Response with SESSIONS (Tag 8002) layout:
                     // Header(10) + ParamSize(4) + Params + SessionArea
                     // We need to skip ParamSize(4)
                     uint32_t off = 10;
                     off += 4; // Skip ParamSize
                     
                     // Read NV Data Size
                     uint16_t r_size = read_be16(rsp_ptr + off); off += 2;
                     print_hex("NV Read Data", rsp_ptr + off, r_size);
                     compare_buffers("NV Verify", nv_data, rsp_ptr + off, 8);
                 } else {
                     printf("NV_Read Failed: 0x%08X\n", rc);
                 }
            } else {
                printf("NV_Write Failed: 0x%08X\n", rc);
            }
        }
    }

    LOS_TaskDelay(5);

    /* -------- 修正版：Test 8: ECC Crypto (CreatePrimary -> Sign -> Flush) --------
    注意：
        - TPM wire format 要求所有整数为大端（BE）。
        - TPM2B_* 结构外层有一个 UINT16 size 字段，内容必须等于后续字节长度（包含内部 size 字段）。
        - 当使用 TPM_ALG_NULL 时，不要写随后的 algorithm-specific 参数。
    */

    #ifndef TPM_ALG_NULL
    /* 如果你的头文件已定义这些宏，请移除这些定义 */
    #define TPM_ALG_NULL        0x0010
    #define TPM_ALG_ECC         0x0023
    #define TPM_ALG_ECDSA       0x0018
    #define TPM_ALG_SHA256      0x000B
    #define TPM_ECC_NIST_P256   0x0003
    #endif

    /* =========================================================================
     * Test 8: ECC Hierarchy (SRK -> Create -> Load -> Sign)
     * ========================================================================= */
    printf("\n--- Test 8: ECC Hierarchy (SRK -> Create -> Load -> Sign) ---\n");
    
    uint32_t srk_handle = 0;
    uint32_t child_handle = 0;
    
    // Buffers to store the created child key blobs (needed for Load)
    static uint8_t child_private_blob[256];
    static uint16_t child_private_size = 0;
    static uint8_t child_public_blob[256];
    static uint16_t child_public_size = 0;

    // -------------------------------------------------------------------------
    // Step 8.1: CreatePrimary (Storage Key / SRK)
    // -------------------------------------------------------------------------
    {
        uint8_t cmd[512]; uint32_t c_off = 0;
        write_be16(cmd + c_off, 0x8002); c_off += 2; // Tag: SESSIONS
        uint32_t size_off = c_off; c_off += 4;
        write_be32(cmd + c_off, 0x00000131); c_off += 4; // CC: CreatePrimary
        
        write_be32(cmd + c_off, 0x40000001); c_off += 4; // Handle: Owner
        c_off += write_password_session(cmd + c_off);    // Auth

        // 1. Sensitive (Empty)
        write_be16(cmd + c_off, 4); c_off += 2;
        write_be16(cmd + c_off, 0); c_off += 2; 
        write_be16(cmd + c_off, 0); c_off += 2;
        
        // 2. Public (TPMT_PUBLIC) - STORAGE KEY TEMPLATE
        uint32_t pub_size_off = c_off; c_off += 2;
        uint32_t pub_start = c_off;
        
        write_be16(cmd + c_off, 0x0023); c_off += 2; // Type: ECC
        write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2; // NameAlg
        
        // Attr: FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth|Decrypt|Restricted
        // Value: 0x00030072 (Standard SRK attributes)
        write_be32(cmd + c_off, 0x00030072); c_off += 4;
        
        write_be16(cmd + c_off, 0); c_off += 2; // AuthPolicy
        
        // ECC Parameters for STORAGE KEY
        write_be16(cmd + c_off, 0x0006); c_off += 2; // Symmetric: AES_128_CFB
        write_be16(cmd + c_off, 0x0000); c_off += 2; // Scheme: Null
        write_be16(cmd + c_off, 0x0003); c_off += 2; // Curve: NIST_P256
        
        /* FIX: KDF cannot be Null for Restricted ECC Keys!
           Use TPM_ALG_KDF_CTR_HMAC_SHA256 (0x0022) with SHA256 (0x000B) */
        write_be16(cmd + c_off, 0x0022); c_off += 2; // KDF Scheme: KDF_CTR_HMAC_SHA256
        write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2; // KDF Hash: SHA256
        
        write_be16(cmd + c_off, 0); c_off += 2; // Unique X
        write_be16(cmd + c_off, 0); c_off += 2; // Unique Y
        
        write_be16(cmd + pub_size_off, c_off - pub_start); // Fix Public Size
        
        write_be16(cmd + c_off, 0); c_off += 2; // OutsideInfo
        write_be32(cmd + c_off, 0); c_off += 4; // PCR Selection
        
        write_be32(cmd + size_off, c_off); // Fix Cmd Size
        
        printf("Sending CreatePrimary (SRK/Storage with KDF)...\n");
        rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
        
        uint32_t rc = read_be32(rsp_ptr + 6);
        if (rc == TPM_RC_SUCCESS) {
            srk_handle = read_be32(rsp_ptr + 14);
            printf("✓ SRK Created. Handle: 0x%08X\n", srk_handle);
        } else {
            printf("CreatePrimary Failed: 0x%08X (Check KDF/Sym support)\n", rc);
        }
    }

    // -------------------------------------------------------------------------
    // Step 8.2: TPM2_Create (Create Child ECC Signing Key)
    // -------------------------------------------------------------------------
    if (srk_handle != 0) {
        uint8_t cmd[512]; uint32_t c_off = 0;
        write_be16(cmd + c_off, 0x8002); c_off += 2; 
        uint32_t size_off = c_off; c_off += 4;
        write_be32(cmd + c_off, 0x00000153); c_off += 4; // CC: TPM2_Create
        
        write_be32(cmd + c_off, srk_handle); c_off += 4; // Handle: Parent (SRK)
        c_off += write_password_session(cmd + c_off);    // Auth for Parent

        // 1. inSensitive (New Key Auth data)
        write_be16(cmd + c_off, 4); c_off += 2;
        write_be16(cmd + c_off, 0); c_off += 2; // No password for child key
        write_be16(cmd + c_off, 0); c_off += 2; // No data
        
        // 2. inPublic (New Key Template)
        uint32_t pub_size_off = c_off; c_off += 2;
        uint32_t pub_start = c_off;
        
        write_be16(cmd + c_off, 0x0023); c_off += 2; // Type: ECC
        write_be16(cmd + c_off, TPM_ALG_SHA256); c_off += 2; 
        
        // Attr: Sign|FixedTPM|FixedParent|SensitiveDataOrigin|UserWithAuth
        // Value: 0x00040072 (Signing Key)
        write_be32(cmd + c_off, 0x00040072); c_off += 4;
        
        write_be16(cmd + c_off, 0); c_off += 2; // Policy
        
        // ECC Params for SIGNING KEY
        write_be16(cmd + c_off, 0x0000); c_off += 2; // Sym: Null
        write_be16(cmd + c_off, 0x0018); c_off += 2; // Scheme: ECDSA
        write_be16(cmd + c_off, 0x0003); c_off += 2; // Curve: NIST_P256
        write_be16(cmd + c_off, 0x0000); c_off += 2; // KDF: Null
        
        write_be16(cmd + c_off, 0); c_off += 2; // Unique X
        write_be16(cmd + c_off, 0); c_off += 2; // Unique Y
        
        write_be16(cmd + pub_size_off, c_off - pub_start);
        
        // 3. OutsideInfo
        write_be16(cmd + c_off, 0); c_off += 2;
        // 4. CreationPCR
        write_be32(cmd + c_off, 0); c_off += 4;
        
        write_be32(cmd + size_off, c_off);
        
        printf("Sending TPM2_Create (Child ECC)...\n");
        rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
        
        uint32_t rc = read_be32(rsp_ptr + 6);
        if (rc == TPM_RC_SUCCESS) {
            printf("✓ Child Key Created (Blob generated).\n");
            
            // Response(8002): Header(10) + ParamSize(4) + outPrivate(TPM2B) + outPublic(TPM2B) ...
            uint32_t off = 14; 
            
            // Capture outPrivate
            child_private_size = read_be16(rsp_ptr + off); off += 2;
            if (child_private_size <= sizeof(child_private_blob)) {
                memcpy(child_private_blob, rsp_ptr + off, child_private_size);
            }
            off += child_private_size;
            
            // Capture outPublic
            child_public_size = read_be16(rsp_ptr + off); off += 2;
            if (child_public_size <= sizeof(child_public_blob)) {
                memcpy(child_public_blob, rsp_ptr + off, child_public_size);
            }
            // print_hex("Child Private", child_private_blob, child_private_size);
            // print_hex("Child Public", child_public_blob, child_public_size);
        } else {
            printf("TPM2_Create Failed: 0x%08X\n", rc);
            // If this fails, srk_handle must be flushed later, but we skip to end
            srk_handle = 0; 
        }
    }

    // -------------------------------------------------------------------------
    // Step 8.3: TPM2_Load (Load Child Key to get Handle)
    // -------------------------------------------------------------------------
    if (child_public_size > 0 && srk_handle != 0) {
        uint8_t cmd[1024]; uint32_t c_off = 0;
        write_be16(cmd + c_off, 0x8002); c_off += 2; 
        uint32_t size_off = c_off; c_off += 4;
        write_be32(cmd + c_off, 0x00000157); c_off += 4; // CC: TPM2_Load
        
        write_be32(cmd + c_off, srk_handle); c_off += 4; // Handle: Parent
        c_off += write_password_session(cmd + c_off);    // Auth for Parent
        
        // 1. inPrivate (TPM2B_PRIVATE) -> Size(2) + Buffer
        write_be16(cmd + c_off, child_private_size); c_off += 2;
        memcpy(cmd + c_off, child_private_blob, child_private_size); c_off += child_private_size;

        // 2. inPublic (TPM2B_PUBLIC) -> Size(2) + Buffer
        write_be16(cmd + c_off, child_public_size); c_off += 2;
        memcpy(cmd + c_off, child_public_blob, child_public_size); c_off += child_public_size;
        
        write_be32(cmd + size_off, c_off);
        
        printf("Sending TPM2_Load...\n");
        rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
        
        uint32_t rc = read_be32(rsp_ptr + 6);
        if (rc == TPM_RC_SUCCESS) {
            // Response(8002): Header(10) + ParamSize(4) + Handle(4) ...
            child_handle = read_be32(rsp_ptr + 14);
            printf("✓ Child Key Loaded. Handle: 0x%08X\n", child_handle);
        } else {
            printf("TPM2_Load Failed: 0x%08X\n", rc);
        }
    }

    // -------------------------------------------------------------------------
    // Step 8.4: TPM2_Sign (Use Child Key)
    // -------------------------------------------------------------------------
    if (child_handle != 0) {
        const uint8_t digest[] = {
            0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2, 0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6, 0x86, 0xcf,
            0x0c, 0x3f, 0x5d, 0x5a, 0x86, 0xaf, 0xf3, 0xca, 0x12, 0x02, 0x0c, 0x92, 0x3a, 0xdc, 0x6c, 0x92
        };

        uint8_t cmd[256]; uint32_t c_off = 0;
        write_be16(cmd + c_off, 0x8002); c_off += 2; 
        uint32_t size_off = c_off; c_off += 4;
        write_be32(cmd + c_off, 0x0000015D); c_off += 4; // CC: Sign
        
        write_be32(cmd + c_off, child_handle); c_off += 4; // Use Child Handle
        c_off += write_password_session(cmd + c_off);      // Auth for Child
        
        // Params
        write_be16(cmd + c_off, 32); c_off += 2;
        memcpy(cmd + c_off, digest, 32); c_off += 32;
        
        // Scheme: Null (Use Key Default: ECDSA)
        write_be16(cmd + c_off, 0x0000); c_off += 2; 
        write_be16(cmd + c_off, 0x0000); c_off += 2; 
        
        // Validation: Null
        write_be16(cmd + c_off, 0x8004); c_off += 2; 
        write_be32(cmd + c_off, 0x40000007); c_off += 4; 
        write_be16(cmd + c_off, 0); c_off += 2; 
        
        write_be32(cmd + size_off, c_off);
        
        printf("Sending ECC Sign (using Loaded Child Key)...\n");
        rsp_size = sizeof(rsp_buf); memset(rsp_buf, 0, rsp_size);
        _plat__RunCommand(c_off, cmd, &rsp_size, (unsigned char**)&rsp_ptr);
        
        uint32_t rc = read_be32(rsp_ptr + 6);
        if (rc == TPM_RC_SUCCESS) {
            uint32_t off = 14; 
            uint16_t sig_alg = read_be16(rsp_ptr + off);
            printf("✓ Signed Successfully. SigAlg: 0x%04X\n", sig_alg);
        } else {
            printf("ECC Sign Failed: 0x%08X\n", rc);
        }
        
        // Flush Child
        {
            uint8_t fcmd[12]; c_off = 0;
            write_be16(fcmd + c_off, TPM_ST_NO_SESSIONS); c_off += 2;
            write_be32(fcmd + c_off, 12); c_off += 4;
            write_be32(fcmd + c_off, 0x00000165); c_off += 4; // Flush
            write_be32(fcmd + c_off, child_handle); c_off += 4;
            rsp_size = sizeof(rsp_buf); _plat__RunCommand(c_off, fcmd, &rsp_size, (unsigned char**)&rsp_ptr);
        }
    }

    // Flush SRK
    if (srk_handle != 0) {
        uint8_t fcmd[12]; uint32_t c_off = 0;
        write_be16(fcmd + c_off, TPM_ST_NO_SESSIONS); c_off += 2;
        write_be32(fcmd + c_off, 12); c_off += 4;
        write_be32(fcmd + c_off, 0x00000165); c_off += 4; // Flush
        write_be32(fcmd + c_off, srk_handle); c_off += 4;
        rsp_size = sizeof(rsp_buf); _plat__RunCommand(c_off, fcmd, &rsp_size, (unsigned char**)&rsp_ptr);
        printf("SRK Flushed.\n");
    }

    printf("\n=== TPM Test Completed ===\n");
}

/* App entry to create the task */
void TPMTestApp(void)
{
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
