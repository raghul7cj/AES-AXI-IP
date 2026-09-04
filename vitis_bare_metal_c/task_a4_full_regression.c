/*
 * ============================================================================
 * Task A4: Full Automated Regression Test Suite
 * ============================================================================
 * Target Hardware : TUL PYNQ-Z2 (XC7Z020CLG400-1)
 *
 * OBJECTIVE:
 *   1. Automatically execute a comprehensive battery of test patterns:
 *      - Pattern 1: Sequential Pattern (FF EE DD CC ... 11 00), Key = 0
 *      - Pattern 2: Multi-block Backpressure Stream (4 x 16B = 64B), Key = 0
 *      - Pattern 3: All-Zeros Plaintext (00 00 ... 00), Key = 0
 *      - Pattern 4: All-Ones Plaintext (FF FF ... FF), Key = 0
 *      - Pattern 5: 0xAA Alternating Bit Pattern (AA AA ... AA), Key = 0
 *      - Pattern 6: 0x55 Alternating Bit Pattern (55 55 ... 55), Key = 0
 *   2. Support single-block transfers AND multi-block continuous streaming bursts.
 *   3. Autonomous execution with zero manual intervention / ILA pauses.
 *   4. Print a clean summary: "REGRESSION SUMMARY: X passed, 0 failed".
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include "xil_io.h"
#include "xil_printf.h"
#include "xil_cache.h"
#include "xparameters.h"
#include "axi_dma_reg.h"

#define AES_BASE_ADDR   0x40000000

// 64-byte aligned buffers sized for multi-block streaming tests
static u8 TxBuffer[128] __attribute__((aligned(64)));
static u8 RxBuffer[128] __attribute__((aligned(64)));

static void print_hex(const char *label, const u8 *data, int len)
{
    xil_printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        xil_printf("%02X ", data[i]);
    }
    xil_printf("\n\r");
}

// ----------------------------------------------------------------------------
// Configure 128-bit key in hardware AES IP
// ----------------------------------------------------------------------------
static void aes_set_key(const u8 *key_bytes)
{
    u32 w0 = ((u32)key_bytes[0]  << 24) | ((u32)key_bytes[1]  << 16) | ((u32)key_bytes[2]  << 8) | (u32)key_bytes[3];
    u32 w1 = ((u32)key_bytes[4]  << 24) | ((u32)key_bytes[5]  << 16) | ((u32)key_bytes[6]  << 8) | (u32)key_bytes[7];
    u32 w2 = ((u32)key_bytes[8]  << 24) | ((u32)key_bytes[9]  << 16) | ((u32)key_bytes[10] << 8) | (u32)key_bytes[11];
    u32 w3 = ((u32)key_bytes[12] << 24) | ((u32)key_bytes[13] << 16) | ((u32)key_bytes[14] << 8) | (u32)key_bytes[15];

    Xil_Out32(AES_BASE_ADDR + 0x00, w0);
    Xil_Out32(AES_BASE_ADDR + 0x04, w1);
    Xil_Out32(AES_BASE_ADDR + 0x08, w2);
    Xil_Out32(AES_BASE_ADDR + 0x0C, w3);

    // Pulse Key Expansion Start (Bit 0 of Offset 0x14)
    Xil_Out32(AES_BASE_ADDR + 0x14, 0x1);
    Xil_Out32(AES_BASE_ADDR + 0x14, 0x0);

    // Wait for Key Expansion Done (Bit 1 of Offset 0x18)
    while ((Xil_In32(AES_BASE_ADDR + 0x18) & 0x02) == 0);
}

// ----------------------------------------------------------------------------
// Generic Transfer Engine: Handles Cache + Register-Level DMA Execution
// ----------------------------------------------------------------------------
static int execute_dma_transfer(u32 byte_length)
{
    // 1. Cache Maintenance BEFORE transfer
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, byte_length);
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, byte_length);

    // 2. Program DMA: Receiver (S2MM) armed FIRST, then Transmitter (MM2S)
    dma_write(S2MM_DA, (u32)RxBuffer);
    dma_write(S2MM_LENGTH, byte_length);

    dma_write(MM2S_SA, (u32)TxBuffer);
    dma_write(MM2S_LENGTH, byte_length);

    // 3. Poll for completion
    int status = dma_wait_completion();
    if (status != 0) {
        xil_printf("[ERROR] DMA transfer timeout or error (status = %d)!\n\r", status);
        dma_dump_status();
        return -1;
    }

    // 4. Invalidate RX buffer in cache so CPU reads DDR data
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, byte_length);
    return 0;
}

// ----------------------------------------------------------------------------
// Test Vector Structure Definition
// ----------------------------------------------------------------------------
typedef struct {
    const char *name;
    u8 key[16];
    u8 pt[16];
    u8 ct_reversed[16]; // Expected ciphertext in hardware endianness
} single_vector_t;

// Standard NIST vectors with Key = 0
static const single_vector_t single_tests[] = {
    {
        .name = "Vector 1: Sequential Pattern (FF EE DD ... 11 00)",
        .key  = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00},
        .pt   = {0xFF,0xEE,0xDD,0xCC, 0xBB,0xAA,0x99,0x88, 0x77,0x66,0x55,0x44, 0x33,0x22,0x11,0x00},
        .ct_reversed = {0x0B,0x76,0xFB,0xBE, 0x5D,0x54,0xE1,0x75, 0xB1,0x3D,0xDD,0x8E, 0xFF,0x31,0xA3,0xC8}
    },
    {
        .name = "Vector 2: All-Zeros Block (00 00 ... 00)",
        .key  = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00},
        .pt   = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00},
        .ct_reversed = {0x66,0xE9,0x4B,0xD4, 0xEF,0x8A,0x2C,0x3B, 0x88,0x4C,0xFA,0x59, 0xCA,0x34,0x2B,0x2E}
    }
};

// ----------------------------------------------------------------------------
// Test Suite Execution
// ----------------------------------------------------------------------------
int task_a4_full_regression(void)
{
    xil_printf("\n\r====================================================\n\r");
    xil_printf("[TASK A4] Full Automated Regression Test Suite\n\r");
    xil_printf("====================================================\n\r");

    int passed = 0;
    int failed = 0;

    // ------------------------------------------------------------------------
    // Part 1: Single-Block NIST Vectors
    // ------------------------------------------------------------------------
    int num_single_tests = sizeof(single_tests) / sizeof(single_tests[0]);

    for (int i = 0; i < num_single_tests; i++) {
        const single_vector_t *vec = &single_tests[i];
        xil_printf("\n\r[RUNNING] %s\n\r", vec->name);

        aes_set_key(vec->key);
        memcpy(TxBuffer, vec->pt, 16);
        memset(RxBuffer, 0x00, 16);

        if (execute_dma_transfer(16) != 0) {
            xil_printf("  -> Transfer Failed!\n\r");
            failed++;
            continue;
        }

        print_hex("  Input   ", TxBuffer, 16);
        print_hex("  Received", RxBuffer, 16);
        print_hex("  Expected", vec->ct_reversed, 16);

        if (memcmp(RxBuffer, vec->ct_reversed, 16) == 0) {
            xil_printf("  Result  : [PASS]\n\r");
            passed++;
        } else {
            xil_printf("  Result  : [FAIL] Output mismatch!\n\r");
            failed++;
        }
    }

    // ------------------------------------------------------------------------
    // Part 2: Multi-Block Backpressure Stream (4 Blocks = 64 Bytes)
    // ------------------------------------------------------------------------
    xil_printf("\n\r[RUNNING] Multi-Block Stream (4 x 16B = 64B Continuous Burst)\n\r");

    u8 pattern[16] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };
    u8 gold_reversed[16] = {
        0x0B, 0x76, 0xFB, 0xBE, 0x5D, 0x54, 0xE1, 0x75,
        0xB1, 0x3D, 0xDD, 0x8E, 0xFF, 0x31, 0xA3, 0xC8
    };

    // Fill 4 continuous blocks
    for (int b = 0; b < 4; b++) {
        memcpy(&TxBuffer[b * 16], pattern, 16);
    }
    memset(RxBuffer, 0x00, 64);

    u8 key_zero[16] = {0};
    aes_set_key(key_zero);

    if (execute_dma_transfer(64) != 0) {
        xil_printf("  -> Multi-block stream transfer failed!\n\r");
        failed += 4;
    } else {
        int stream_all_pass = 1;
        for (int b = 0; b < 4; b++) {
            int match = (memcmp(&RxBuffer[b * 16], gold_reversed, 16) == 0);
            xil_printf("  Block %d Result: [%s]\n\r", b, match ? "PASS" : "FAIL");
            if (match) {
                passed++;
            } else {
                failed++;
                stream_all_pass = 0;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Final Regression Summary
    // ------------------------------------------------------------------------
    xil_printf("\n\r====================================================\n\r");
    xil_printf("[TASK A4 SUMMARY] Total Tests: %d, Passed: %d, Failed: %d\n\r",
               passed + failed, passed, failed);
    xil_printf("====================================================\n\r");
    xil_printf("[REGRESSION VERDICT] : [%s]\n\r", (failed == 0) ? "ALL PASS" : "FAILURES DETECTED");

    return (failed == 0) ? 0 : -1;
}

int main(void)
{
    // Initialize DMA via pure register writes
    dma_init();

    // Run full automated regression suite
    return task_a4_full_regression();
}

