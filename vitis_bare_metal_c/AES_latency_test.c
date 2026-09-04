#include "axi_dma_reg.h"
#include "xil_cache.h"
#include <string.h>

#define MAX_STREAM_BYTES (64 * 1024) // 64 KB heavy stream

static u8 BigTxBuf[MAX_STREAM_BYTES] __attribute__((aligned(64)));
static u8 BigRxBuf[MAX_STREAM_BYTES] __attribute__((aligned(64)));

// Enable Cortex-A9 Cycle Counter via CP15
static inline void pmu_init_ccnt(void) {
    u32 val;
    // Enable performance counters + reset cycle counter
    asm volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(val));
    val |= 0x5; // PMCR_E | PMCR_C
    asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(val));
    // Enable cycle count register (bit 31)
    asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x80000000));
}

static inline u32 pmu_get_ccnt(void) {
    u32 cycles;
    asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(cycles));
    return cycles;
}

// ----------------------------------------------------------------------------
// Test A: Sparse (Ping-Pong 1-Block Transfers)
// Simulates intermittent crypto packet processing with per-block DMA triggering
// ----------------------------------------------------------------------------
void benchmark_sparse(int iterations) {
    u32 start_cycles, end_cycles;
    u32 total_bytes = iterations * 16;

    Xil_DCacheFlushRange((UINTPTR)BigTxBuf, 16);
    Xil_DCacheInvalidateRange((UINTPTR)BigRxBuf, 16);

    pmu_init_ccnt();
    start_cycles = pmu_get_ccnt();

    for (int i = 0; i < iterations; i++) {
        dma_s2mm_start((UINTPTR)BigRxBuf, 16);
        dma_mm2s_start((UINTPTR)BigTxBuf, 16);
        if (dma_wait_completion() != 0) {
            xil_printf("Sparse failure at iter %d\n\r", i);
            return;
        }
    }

    end_cycles = pmu_get_ccnt();
    u32 delta = end_cycles - start_cycles;

    // ARM Cortex-A9 on PYNQ-Z2 default = 650 MHz
    float elapsed_sec = (float)delta / 650000000.0f;
    float mbps = ((float)total_bytes * 8.0f) / (elapsed_sec * 1000000.0f);

    xil_printf("\n\r--- SPARSE WORKLOAD (Single-Block x %d) ---\n\r", iterations);
    xil_printf("Total Cycles : %u\n\r", delta);
    xil_printf("Cycles/Block : %u\n\r", delta / iterations);
    xil_printf("Throughput   : %d.%02d Mbps\n\r", (int)mbps, ((int)(mbps * 100)) % 100);
}

// ----------------------------------------------------------------------------
// Test B: Block-Heavy (Continuous Burst Multi-KB Stream)
// Saturates AXI bus and exposes backpressure/stall cycles in AES pipeline
// ----------------------------------------------------------------------------
void benchmark_block_heavy(u32 stream_len) {
    u32 start_cycles, end_cycles;

    memset(BigTxBuf, 0x5A, stream_len);
    memset(BigRxBuf, 0x00, stream_len);

    Xil_DCacheFlushRange((UINTPTR)BigTxBuf, stream_len);
    Xil_DCacheInvalidateRange((UINTPTR)BigRxBuf, stream_len);

    pmu_init_ccnt();
    start_cycles = pmu_get_ccnt();

    // Fire continuous batch transfer
    dma_s2mm_start((UINTPTR)BigRxBuf, stream_len);
    dma_mm2s_start((UINTPTR)BigTxBuf, stream_len);

    if (dma_wait_completion() != 0) {
        xil_printf("Block-heavy failure\n\r");
        return;
    }

    end_cycles = pmu_get_ccnt();
    u32 delta = end_cycles - start_cycles;

    float elapsed_sec = (float)delta / 650000000.0f;
    float mbps = ((float)stream_len * 8.0f) / (elapsed_sec * 1000000.0f);

    xil_printf("\n\r--- BLOCK-HEAVY WORKLOAD (%d Bytes) ---\n\r", stream_len);
    xil_printf("Total Cycles : %u\n\r", delta);
    xil_printf("Throughput   : %d.%02d Mbps\n\r", (int)mbps, ((int)(mbps * 100)) % 100);
}