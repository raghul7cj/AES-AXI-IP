/*
 * ============================================================================
 * Task A3 Template: First Correct Single-Block Transfer & Cache Coherency
 * ============================================================================
 * Target Hardware : TUL PYNQ-Z2 (XC7Z020CLG400-1)
 *
 * OBJECTIVE:
 *   1. Initialize AES-128 Key registers in hardware.
 *   2. Prepare a 16-byte plaintext buffer and 16-byte ciphertext buffer (64-byte aligned).
 *   3. Perform Cache Flush on TxBuffer and Cache Invalidate on RxBuffer.
 *   4. Arm S2MM (Receiver) BEFORE triggering MM2S (Transmitter).
 *   5. Poll for transfer completion and clear completion flags (W1C).
 *   6. Invalidate RxBuffer in Cache so CPU reads fresh DDR data.
 *   7. Compare received ciphertext against the expected NIST gold vector.
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

// Cache-line aligned buffers (64-byte alignment avoids false cache sharing)
static u8 TxBuffer[64] __attribute__((aligned(64)));
static u8 RxBuffer[64] __attribute__((aligned(64)));

static void print_hex(const char *label, const u8 *data, int len)
{
    xil_printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        xil_printf("%02X ", data[i]);
    }
    xil_printf("\n\r");
}

// Helper: Configure 128-bit key in hardware AES IP
void aes_set_key(const u8 *key_bytes)
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

int task_a3_first_correct_transfer(void)
{
    xil_printf("\n\r====================================================\n\r");
    xil_printf("[TASK A3] First Correct Transfer (16-byte Block)\n\r");
    xil_printf("====================================================\n\r");

    // ------------------------------------------------------------------------
    // Step 1: Configure Key = 0 in AES IP
    // ------------------------------------------------------------------------
    u8 key[16] = {0};
    aes_set_key(key);
    xil_printf("[A3] 1. AES Key configured (Key = 0).\n\r");

    // ------------------------------------------------------------------------
    // Step 2: Prepare Input Pattern & Expected Gold Output
    // ------------------------------------------------------------------------
    u8 plaintext[16] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
    };

    // Expected ciphertext from hardware core (reversed endianness format)
    u8 expected_ciphertext[16] = {
        0x0B, 0x76, 0xFB, 0xBE, 0x5D, 0x54, 0xE1, 0x75,
        0xB1, 0x3D, 0xDD, 0x8E, 0xFF, 0x31, 0xA3, 0xC8
    };

    memcpy(TxBuffer, plaintext, 16);
    memset(RxBuffer, 0x00, 16);

    // ------------------------------------------------------------------------
    // Step 3: Cache Maintenance BEFORE DMA transfer
    // Flush TX: Push dirty cache lines of TxBuffer into physical DDR
    // Invalidate RX: Discard stale cache lines of RxBuffer in CPU cache
    // ------------------------------------------------------------------------
    xil_printf("[A3] 2. Performing Cache Maintenance (Flush TX, Invalidate RX)...\n\r");
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, 16);   
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);


    // ------------------------------------------------------------------------
    // Step 4: Program DMA - CRITICAL: Arm RX (S2MM) BEFORE TX (MM2S)
    // Hint:
    //   1. Write RxBuffer DDR address to S2MM_DA
    //   2. Write transfer length (16) to S2MM_LENGTH (Arms S2MM engine)
    //   3. Write TxBuffer DDR address to MM2S_SA
    //   4. Write transfer length (16) to MM2S_LENGTH (Starts MM2S burst)
    // ------------------------------------------------------------------------
    xil_printf("[A3] 3. Triggering DMA (S2MM armed first, then MM2S fired)...\n\r");
    // TODO: Write destination address to S2MM_DA
    dma_write(S2MM_DA, (u32)RxBuffer);
    // TODO: Write length (16) to S2MM_LENGTH
    dma_write(S2MM_LENGTH, 16);
    // TODO: Write source address to MM2S_SA
    dma_write(MM2S_SA, (u32)TxBuffer);
    // TODO: Write length (16) to MM2S_LENGTH
    dma_write(MM2S_LENGTH, 16);

    // ------------------------------------------------------------------------
    // Step 5: Wait for DMA completion
    // Hint: Poll until dma_wait_completion() returns 0 or poll IOC/Idle bits
    // ------------------------------------------------------------------------
    xil_printf("[A3] 4. Waiting for transfer completion...\n\r");
    // TODO: Wait for completion and verify return code
    int status = dma_wait_completion();
    if (status != 0) {
        xil_printf("[A3 FAIL] DMA transfer timed out or encountered an error (status = %d)!\n\r", status);
        dma_dump_status();
        return -1;
    }


    // ------------------------------------------------------------------------
    // Step 6: Cache Maintenance AFTER DMA transfer
    // Invalidate RX: Force CPU to read the freshly written ciphertext from DDR
    // ------------------------------------------------------------------------
    xil_printf("[A3] 5. Invalidating RxBuffer cache range before CPU read...\n\r");
    // TODO: Call Xil_DCacheInvalidateRange on RxBuffer (16 bytes)
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);

    // ------------------------------------------------------------------------
    // Step 7: Verification & Comparison
    // ------------------------------------------------------------------------
    print_hex("Plaintext Input    ", TxBuffer, 16);
    print_hex("Ciphertext Received", RxBuffer, 16);
    print_hex("Ciphertext Expected", expected_ciphertext, 16);

    int match = (memcmp(RxBuffer, expected_ciphertext, 16) == 0);
    xil_printf("[TASK A3 VERDICT] : [%s]\n\r", match ? "PASS" : "FAIL");

    return match ? 0 : -1;
}

int main(void)
{
    // Make sure DMA is initialized first (from Task A2)
    dma_init();

    // Run Task A3
    return task_a3_first_correct_transfer();
}