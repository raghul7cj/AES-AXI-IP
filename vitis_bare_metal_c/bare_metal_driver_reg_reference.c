/*
 * ============================================================================
 * AES-128 Pattern Sensitivity Test with ILA Debug Support
 * ============================================================================
 * Hardware: Pynq-Z2, Custom AES-128 IP, AXI DMA, UART1 (115200)
 * Toolchain: Vivado/Vitis 2022.2
 *
 * PURPOSE:
 *   - Test AES core with various input patterns.
 *   - Known issue: All non-zero inputs fail; only 0x00 works.
 *   - Pause execution before the 0xFF test to allow ILA triggering.
 *   - Added multiblock test (10 NIST vectors) to observe backpressure.
 *
 * USAGE (ILA capture):
 *   1. Open TeraTerm (115200, 8N1) and connect to Pynq-Z2 COM port.
 *   2. In Vitis, build and launch hardware debug.
 *   3. Set a breakpoint at wait_for_ila_setup() call (inside run_vector).
 *   4. Run to breakpoint (program stops before 0xFF transfer).
 *   5. Switch to Vivado Hardware Manager, program FPGA with ILA bitstream.
 *   6. Arm ILA trigger: s_axis_tdata != 0  OR  (tvalid==1 && tready==0).
 *   7. Return to TeraTerm, press ANY key.
 *   8. DMA starts, ILA triggers -> capture waveform.
 *   9. After capture, you can continue or terminate.
 *
 * NORMAL OPERATION (no debug):
 *   - Comment out the wait_for_ila_setup() line in run_vector().
 *   - The test suite will run all patterns automatically.
 *
 * ============================================================================
 */
/*
 * ============================================================================
 * AES-128 BackPressure Test (4× repeated block, key=0)
 * ============================================================================
 * Sends the same 16byte pattern four times in one DMA stream.
 * Captures backpressure if the core needs idle cycles between blocks.
 *
 * Pattern:     00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
 * Ciphertext:  c8 a3 31 ff 8e dd 3d b1 75 e1 54 5d be fb 76 0b
 *
 * ILA trigger: s_axis_tvalid == 1 && s_axis_tready == 0
 * ============================================================================
 */
/*
 * ============================================================================
 * AES-128 Back‑Pressure Test (4× repeated block, key=0)
 * ============================================================================
 * Sends the same 16‑byte pattern four times in one DMA stream.
 * Captures back‑pressure if the core needs idle cycles between blocks.
 *
 * Pattern:     00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
 * Ciphertext:  c8 a3 31 ff 8e dd 3d b1 75 e1 54 5d be fb 76 0b
 *              (provided by user)
 *
 * NOTE: The comparison is done after byte‑reversing the expected cipher
 *       to match the hardware's endianness (if needed). Both original and
 *       reversed expected values are printed.
 *
 * ILA trigger: s_axis_tvalid == 1 && s_axis_tready == 0
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include "xil_cache.h"
#include "xil_printf.h"
#include "xparameters.h"
#include "xaxidma.h"
#include "xil_io.h"

#define AES_BASE   XPAR_AXI_AES_IP_0_BASEADDR
#define DMA_DEV_ID XPAR_AXIDMA_0_DEVICE_ID

XAxiDma AxiDma;
u8 TxBuffer[128] __attribute__ ((aligned(64)));  // 4 blocks = 64 bytes
u8 RxBuffer[128] __attribute__ ((aligned(64)));

void wait_for_ila_setup(void)
{
    xil_printf("\n\r========================================\n\r");
    xil_printf("ILA SETUP - DEBUG PAUSE\n\r");
    xil_printf("Set trigger: (tvalid==1) && (tready==0)\n\r");
    xil_printf("Press any key in TeraTerm to continue...\n\r");
    while (inbyte() == 0);
    xil_printf("Resuming...\n\r");
}

void print_hex(const char* label, u8* data, int len)
{
    xil_printf("%s: ", label);
    for (int i = 0; i < len; i++) xil_printf("%02X ", data[i]);
    xil_printf("\n\r");
}

void run_backpressure_test(void)
{
    // --------------------------------------------------------------------
    // Pattern: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
    // --------------------------------------------------------------------
	u8 pattern[16] = {
	    0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
	    0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
	};

    // Expected ciphertext as provided (original order)
    u8 gold_original[16] = {
        0xc8,0xa3,0x31,0xff,0x8e,0xdd,0x3d,0xb1,
        0x75,0xe1,0x54,0x5d,0xbe,0xfb,0x76,0x0b
    };

    u8 gold_reversed[16] = {
        0x0b, 0x76, 0xfb, 0xbe,
        0x5d, 0x54, 0xe1, 0x75,
        0xb1, 0x3d, 0xdd, 0x8e,
        0xff, 0x31, 0xa3, 0xc8
    };

    // Build transmit buffer: four copies of pattern
    for (int i = 0; i < 4; i++) {
        memcpy(&TxBuffer[i*16], pattern, 16);
    }

    // Prepare Rx buffer
    memset(RxBuffer, 0, 64);

    // Cache maintenance
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, 64);
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 64);

    // Start DMA (RX first, then TX)
    XAxiDma_SimpleTransfer(&AxiDma, (UINTPTR)RxBuffer, 64, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_SimpleTransfer(&AxiDma, (UINTPTR)TxBuffer, 64, XAXIDMA_DMA_TO_DEVICE);

    // Wait for completion
    while (XAxiDma_Busy(&AxiDma, XAXIDMA_DMA_TO_DEVICE));
    while (XAxiDma_Busy(&AxiDma, XAXIDMA_DEVICE_TO_DMA));

    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 64);

    // Display results
    xil_printf("\n\r--- BACK‑PRESSURE TEST (4 blocks) ---\n\r");
    xil_printf("Expected (original) : ");
    print_hex("", gold_original, 16);
    xil_printf("Expected (reversed) : ");
    print_hex("", gold_reversed, 16);

    for (int i = 0; i < 4; i++) {
        xil_printf("Block %d:\n\r", i);
        print_hex("  Input   ", &TxBuffer[i*16], 16);
        print_hex("  Received", &RxBuffer[i*16], 16);
        int match = (memcmp(&RxBuffer[i*16], gold_reversed, 16) == 0);
        xil_printf("  Result  : [%s] (using reversed expected)\n\r", match ? "PASS" : "FAIL");
    }
}

int main(void)
{
    XAxiDma_Config *CfgPtr;

    xil_printf("\n\r=== AES-128 BACK‑PRESSURE TEST ===\n\r");

    // Init DMA
    CfgPtr = XAxiDma_LookupConfig(DMA_DEV_ID);
    XAxiDma_CfgInitialize(&AxiDma, CfgPtr);
    XAxiDma_IntrDisable(&AxiDma, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_IntrDisable(&AxiDma, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DMA_TO_DEVICE);

    // Set key = 0
    Xil_Out32(AES_BASE + 0x00, 0);
    Xil_Out32(AES_BASE + 0x04, 0);
    Xil_Out32(AES_BASE + 0x08, 0);
    Xil_Out32(AES_BASE + 0x0C, 0);
    Xil_Out32(AES_BASE + 0x14, 0x1);  // start key expansion
    Xil_Out32(AES_BASE + 0x14, 0x0);
    while ((Xil_In32(AES_BASE + 0x18) & 0x02) == 0);  // wait for done

    // Optional: pause before transfer to set up ILA
    wait_for_ila_setup();   // Comment out if not debugging

    // Run the test
    run_backpressure_test();

    xil_printf("\n\r=== TEST COMPLETE ===\n\r");
    return 0;
}
