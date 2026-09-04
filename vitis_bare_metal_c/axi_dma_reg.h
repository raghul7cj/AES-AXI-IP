#ifndef AXI_DMA_REG_H
#define AXI_DMA_REG_H

#include "xil_io.h"
#include "xil_printf.h"
#include "xparameters.h"

// ============================================================================
// Base Address
// ============================================================================
#ifdef XPAR_AXIDMA_0_BASEADDR
#define DMA_BASE            XPAR_AXIDMA_0_BASEADDR
#elif defined(XPAR_AXI_DMA_0_BASEADDR)
#define DMA_BASE            XPAR_AXI_DMA_0_BASEADDR
#else
#define DMA_BASE            0x40400000  // Base address from Vivado Block Diagram
#endif

// ============================================================================
// Register Offsets (Direct Register / Simple DMA Mode)
// ============================================================================
#define MM2S_DMACR          0x00    // MM2S Control Register
#define MM2S_DMASR          0x04    // MM2S Status Register
#define MM2S_SA             0x18    // MM2S Source Address (32-bit DDR physical address)
#define MM2S_LENGTH         0x28    // MM2S Transfer Length (Writing triggers TX)

#define S2MM_DMACR          0x30    // S2MM Control Register
#define S2MM_DMASR          0x34    // S2MM Status Register
#define S2MM_DA             0x48    // S2MM Destination Address (32-bit DDR physical address)
#define S2MM_LENGTH         0x58    // S2MM Transfer Length (Writing triggers RX)

// ============================================================================
// Bitfield Masks
// ============================================================================
#define DMACR_RS            (1 << 0)   // Bit 0: Run/Stop (1 = Run, 0 = Stop)
#define DMACR_RESET         (1 << 2)   // Bit 2: Soft Reset (self-clears when done)

#define DMASR_HALTED        (1 << 0)   // Bit 0: 1 = Halted, 0 = Running
#define DMASR_IDLE          (1 << 1)   // Bit 1: 1 = Idle, 0 = Busy transferring
#define DMASR_IOC_IRQ       (1 << 12)  // Bit 12: Transfer Complete flag (Write 1 to clear)
#define DMASR_ERR_MASK      (0x70)     // Bits 4,5,6: Error flags (DMAIntErr, DMASlvErr, DMADecErr)

// ============================================================================
// Low-Level Register Access Helpers
// ============================================================================
static inline void dma_write(u32 offset, u32 value)
{
    Xil_Out32(DMA_BASE + offset, value);
}

static inline u32 dma_read(u32 offset)
{
    return Xil_In32(DMA_BASE + offset);
}

// ============================================================================
// Register Diagnostics
// ============================================================================
static inline void dma_dump_status(void)
{
    u32 mm2s_sr = dma_read(MM2S_DMASR);
    u32 s2mm_sr = dma_read(S2MM_DMASR);
    xil_printf("DMA Register Dump:\n\r");
    xil_printf("  MM2S_DMACR : 0x%08X\n\r", dma_read(MM2S_DMACR));
    xil_printf("  MM2S_DMASR : 0x%08X (Halted=%d, Idle=%d, IOC=%d, Err=%d)\n\r",
               mm2s_sr,
               !!(mm2s_sr & DMASR_HALTED),
               !!(mm2s_sr & DMASR_IDLE),
               !!(mm2s_sr & DMASR_IOC_IRQ),
               !!(mm2s_sr & DMASR_ERR_MASK));
    xil_printf("  S2MM_DMACR : 0x%08X\n\r", dma_read(S2MM_DMACR));
    xil_printf("  S2MM_DMASR : 0x%08X (Halted=%d, Idle=%d, IOC=%d, Err=%d)\n\r",
               s2mm_sr,
               !!(s2mm_sr & DMASR_HALTED),
               !!(s2mm_sr & DMASR_IDLE),
               !!(s2mm_sr & DMASR_IOC_IRQ),
               !!(s2mm_sr & DMASR_ERR_MASK));
}

// ============================================================================
// Initialization & Reset
// ============================================================================
static inline int dma_init(void)
{
    xil_printf("[DMA] Initializing Register-Level DMA @ 0x%08X...\n\r", (u32)DMA_BASE);

    // 1. Soft Reset both channels
    dma_write(MM2S_DMACR, DMACR_RESET);
    dma_write(S2MM_DMACR, DMACR_RESET);

    // 2. Poll until reset completes (DMACR_RESET auto-clears to 0)
    while (dma_read(MM2S_DMACR) & DMACR_RESET);
    while (dma_read(S2MM_DMACR) & DMACR_RESET);

    // 3. Clear any pending status/interrupt flags (W1C: Write-1-to-Clear)
    dma_write(MM2S_DMASR, DMASR_IOC_IRQ | DMASR_ERR_MASK);
    dma_write(S2MM_DMASR, DMASR_IOC_IRQ | DMASR_ERR_MASK);

    // 4. Start both channels by setting Run/Stop (RS = 1)
    dma_write(MM2S_DMACR, DMACR_RS);
    dma_write(S2MM_DMACR, DMACR_RS);

    // 5. Wait until channels exit the Halted state (HALTED bit drops to 0)
    while (dma_read(MM2S_DMASR) & DMASR_HALTED);
    while (dma_read(S2MM_DMASR) & DMASR_HALTED);

    xil_printf("[DMA] Initialization complete. Both channels running and ready.\n\r");
    return 0;
}

// ============================================================================
// Transfer Triggers
// ============================================================================
static inline void dma_s2mm_start(UINTPTR dst_addr, u32 length)
{
    dma_write(S2MM_DA, (u32)dst_addr);
    dma_write(S2MM_LENGTH, length);  // Writing length arms/starts S2MM
}

static inline void dma_mm2s_start(UINTPTR src_addr, u32 length)
{
    dma_write(MM2S_SA, (u32)src_addr);
    dma_write(MM2S_LENGTH, length);  // Writing length fires MM2S
}

// ============================================================================
// Status & Completion Polling
// ============================================================================
static inline int dma_mm2s_busy(void)
{
    return !(dma_read(MM2S_DMASR) & DMASR_IDLE);
}

static inline int dma_s2mm_busy(void)
{
    return !(dma_read(S2MM_DMASR) & DMASR_IDLE);
}

static inline int dma_wait_completion(void)
{
    int timeout;

    // 1. Wait for MM2S (TX) transfer with timeout protection
    timeout = 10000000;
    while (dma_mm2s_busy() && --timeout) {
        u32 status_mm2s = dma_read(MM2S_DMASR);
        if (status_mm2s & DMASR_ERR_MASK) {
            xil_printf("[DMA ERROR] MM2S Error detected: DMASR = 0x%08X\n\r", status_mm2s);
            return -1;
        }
    }
    if (timeout == 0) {
        xil_printf("[DMA TIMEOUT] MM2S transfer timed out! Pipeline stalled.\n\r");
        return -2;
    }
    // Verify and clear IOC flag (W1C)
    if (dma_read(MM2S_DMASR) & DMASR_IOC_IRQ) {
        dma_write(MM2S_DMASR, DMASR_IOC_IRQ);
    }

    // 2. Wait for S2MM (RX) transfer with timeout protection
    timeout = 10000000;
    while (dma_s2mm_busy() && --timeout) {
        u32 status_s2mm = dma_read(S2MM_DMASR);
        if (status_s2mm & DMASR_ERR_MASK) {
            xil_printf("[DMA ERROR] S2MM Error detected: DMASR = 0x%08X\n\r", status_s2mm);
            return -1;
        }
    }
    if (timeout == 0) {
        xil_printf("[DMA TIMEOUT] S2MM transfer timed out! Missing TLAST or byte count mismatch.\n\r");
        return -3;
    }
    // Verify and clear IOC flag (W1C)
    if (dma_read(S2MM_DMASR) & DMASR_IOC_IRQ) {
        dma_write(S2MM_DMASR, DMASR_IOC_IRQ);
    }

    return 0;
}

#endif // AXI_DMA_REG_H
