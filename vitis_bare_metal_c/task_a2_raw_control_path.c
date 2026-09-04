/*
 * ============================================================================
 * Task A2: Raw Control Path & DMA State Machine Verification
 * ============================================================================
 * Target Hardware : TUL PYNQ-Z2 (XC7Z020CLG400-1)
 *
 * OBJECTIVE:
 *   1. Issue a Soft Reset to both MM2S and S2MM channels using pure register writes.
 *   2. Poll until the hardware self-clearing reset bit drops to 0.
 *   3. Clear residual status flags using Write-1-to-Clear (W1C).
 *   4. Start both channels by setting Run/Stop (RS = 1).
 *   5. Poll and verify that the Halted bit de-asserts (Halted = 0).
 *
 * RULES:
 *   - Use ONLY raw Xil_In32 / Xil_Out32 (or dma_read / dma_write from axi_dma_reg.h).
 *   - Zero high-level driver APIs.
 * ============================================================================
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "xil_io.h"
#include "xil_printf.h"
#include "xparameters.h"
#include "axi_dma_reg.h"

int task_a2_raw_control_path(void)
{
    xil_printf("\n\r====================================================\n\r");
    xil_printf("[TASK A2] Raw Control Path & DMA Bringup\n\r");
    xil_printf("====================================================\n\r");

    // ------------------------------------------------------------------------
    // Step 1: Soft Reset both MM2S and S2MM channels
    // ------------------------------------------------------------------------
    xil_printf("[A2] 1. Asserting Soft Reset...\n\r");
    dma_write(MM2S_DMACR, DMACR_RESET);
    dma_write(S2MM_DMACR, DMACR_RESET);

    // ------------------------------------------------------------------------
    // Step 2: Poll until hardware finishes resetting (DMACR_RESET auto-clears)
    // ------------------------------------------------------------------------
    xil_printf("[A2] 2. Polling for reset completion...\n\r");
    uint32_t timeout = 1000000;
    while ((dma_read(MM2S_DMACR) & DMACR_RESET) || (dma_read(S2MM_DMACR) & DMACR_RESET)) {
        timeout--;
        if (timeout == 0) {
            xil_printf("[A2] 2. FAILED - Timeout waiting for reset to clear!\n\r");
            return -1;
        }
    }
    xil_printf("[A2]    Soft reset complete (engines quiesced).\n\r");

    // ------------------------------------------------------------------------
    // Step 3: Clear any pending status and error flags (W1C: Write-1-to-Clear)
    // ------------------------------------------------------------------------
    xil_printf("[A2] 3. Clearing status flags (W1C)...\n\r");
    u32 mm2s_flags = dma_read(MM2S_DMASR) & (DMASR_IOC_IRQ | DMASR_ERR_MASK);
    if (mm2s_flags) {
        dma_write(MM2S_DMASR, mm2s_flags);
        xil_printf("[A2]    MM2S_DMASR flags (0x%08X) cleared.\n\r", mm2s_flags);
    } else {
        xil_printf("[A2]    MM2S_DMASR already clean.\n\r");
    }

    u32 s2mm_flags = dma_read(S2MM_DMASR) & (DMASR_IOC_IRQ | DMASR_ERR_MASK);
    if (s2mm_flags) {
        dma_write(S2MM_DMASR, s2mm_flags);
        xil_printf("[A2]    S2MM_DMASR flags (0x%08X) cleared.\n\r", s2mm_flags);
    } else {
        xil_printf("[A2]    S2MM_DMASR already clean.\n\r");
    }

    // ------------------------------------------------------------------------
    // Step 4: Check and print status before starting
    // ------------------------------------------------------------------------
    u32 mm2s_sr = dma_read(MM2S_DMASR);
    u32 s2mm_sr = dma_read(S2MM_DMASR);
    xil_printf("[A2]    Pre-run status: MM2S_DMASR=0x%08X (Halted=%d), S2MM_DMASR=0x%08X (Halted=%d)\n\r",
               mm2s_sr, !!(mm2s_sr & DMASR_HALTED),
               s2mm_sr, !!(s2mm_sr & DMASR_HALTED));

    // ------------------------------------------------------------------------
    // Step 5: Start both DMA channels (RS = 1)
    // ------------------------------------------------------------------------
    xil_printf("[A2] 4. Starting channels (RS = 1)...\n\r");
    dma_write(MM2S_DMACR, DMACR_RS);
    dma_write(S2MM_DMACR, DMACR_RS);

    // ------------------------------------------------------------------------
    // Step 6: Poll and confirm Halted bit drops to 0
    // ------------------------------------------------------------------------
    xil_printf("[A2] 5. Polling until Halted == 0...\n\r");
    timeout = 1000000;
    while (dma_read(MM2S_DMACR) & DMASR_HALTED) {
        timeout--;
        if (timeout == 0) {
            xil_printf("[A2] 5. FAILED - Timeout waiting for MM2S Halted to clear!\n\r");
            break;
        }
    }

    timeout = 1000000;
    while (dma_read(S2MM_DMASR) & DMASR_HALTED) {
        timeout--;
        if (timeout == 0) {
            xil_printf("[A2] 5. FAILED - Timeout waiting for S2MM Halted to clear!\n\r");
            break;
        }
    }

    // ------------------------------------------------------------------------
    // Step 7: Verify final state
    // ------------------------------------------------------------------------
    mm2s_sr = dma_read(MM2S_DMASR);
    s2mm_sr = dma_read(S2MM_DMASR);
    xil_printf("[A2]    Post-run status: MM2S_DMASR=0x%08X (Halted=%d, Idle=%d)\n\r",
               mm2s_sr, !!(mm2s_sr & DMASR_HALTED), !!(mm2s_sr & DMASR_IDLE));
    xil_printf("[A2]    Post-run status: S2MM_DMASR=0x%08X (Halted=%d, Idle=%d)\n\r",
               s2mm_sr, !!(s2mm_sr & DMASR_HALTED), !!(s2mm_sr & DMASR_IDLE));

    int pass = ((mm2s_sr & DMASR_HALTED) == 0) && ((s2mm_sr & DMASR_HALTED) == 0);
    xil_printf("[TASK A2 VERDICT] : [%s]\n\r", pass ? "PASS" : "FAIL");
    return pass ? 0 : -1;
}

int main(void)
{
    return task_a2_raw_control_path();
}

