/*
 * ============================================================================
 * Task A6 Part 2: High-Throughput Burst Streaming & Scalability Benchmark
 * ============================================================================
 * Target Hardware : TUL PYNQ-Z2 (XC7Z020CLG400-1)
 * PL Clock        : 75.0 MHz
 * PS CPU Clock    : 650.0 MHz (Global Timer COUNTS_PER_SECOND = 325 MHz)
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include "xtime_l.h"
#include "xil_printf.h"
#include "xil_cache.h"
#include "xparameters.h"
#include "xaxidma.h"
#include "axi_dma_reg.h"

#define AES_BASE_ADDR       0x40000000
#define DMA_DEV_ID          XPAR_AXIDMA_0_DEVICE_ID
#define MAX_STREAM_BYTES    (8 * 1024) // 8 KB safe maximum for C_SG_LENGTH_WIDTH = 14

// 64-byte aligned DMA buffers
static u8 TxBuffer[MAX_STREAM_BYTES] __attribute__((aligned(64)));
static u8 RxBuffer[MAX_STREAM_BYTES] __attribute__((aligned(64)));

static XAxiDma AxiDmaInstance;

// Sweep sizes up to 8 KB (512 AES blocks)
static const u32 test_sizes[] = {
    16,          // 1 Block
    64,          // 4 Blocks
    256,         // 16 Blocks
    512,         // 32 Blocks
    1024,        // 64 Blocks (1 KB)
    2048,        // 128 Blocks (2 KB)
    4096,        // 256 Blocks (4 KB)
    8192         // 512 Blocks (8 KB)
};

static inline void get_precise_time(XTime *t)
{
    asm volatile("dsb sy; isb" ::: "memory");
    XTime_GetTime(t);
    asm volatile("dsb sy; isb" ::: "memory");
}

static inline double ticks_to_us(XTime ticks)
{
    return ((double)ticks * 1000000.0) / (double)COUNTS_PER_SECOND;
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

    Xil_Out32(AES_BASE_ADDR + 0x14, 0x1);
    Xil_Out32(AES_BASE_ADDR + 0x14, 0x0);

    while ((Xil_In32(AES_BASE_ADDR + 0x18) & 0x02) == 0);
}

// ----------------------------------------------------------------------------
// Custom Register Throughput Benchmark with Automatic Channel Activation
// ----------------------------------------------------------------------------
static int benchmark_custom_driver_throughput(u32 len, double *out_time_us, double *out_mbps)
{
    XTime t_start, t_end;
    uint32_t timeout;

    // Cache flush TX
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, len);

    get_precise_time(&t_start);

    // Ensure channels are Running (RS = 1)
    if (dma_read(MM2S_DMASR) & DMASR_HALTED) {
        dma_write(MM2S_DMACR, DMACR_RS);
        while (dma_read(MM2S_DMASR) & DMASR_HALTED);
    }
    if (dma_read(S2MM_DMASR) & DMASR_HALTED) {
        dma_write(S2MM_DMACR, DMACR_RS);
        while (dma_read(S2MM_DMASR) & DMASR_HALTED);
    }

    // Direct Register DMA trigger
    dma_write(S2MM_DA, (u32)RxBuffer);
    dma_write(S2MM_LENGTH, len);
    dma_write(MM2S_SA, (u32)TxBuffer);
    dma_write(MM2S_LENGTH, len);

    // Wait completion with timeout
    timeout = 10000000;
    while (dma_mm2s_busy()) {
        if (--timeout == 0) {
            xil_printf("\n\r[ERROR] Custom MM2S timeout at len = %u!\n\r", (unsigned int)len);
            dma_dump_status();
            return -1;
        }
    }

    timeout = 10000000;
    while (dma_s2mm_busy()) {
        if (--timeout == 0) {
            xil_printf("\n\r[ERROR] Custom S2MM timeout at len = %u!\n\r", (unsigned int)len);
            dma_dump_status();
            return -1;
        }
    }

    // Clear IOC flags (W1C)
    dma_write(MM2S_DMASR, DMASR_IOC_IRQ);
    dma_write(S2MM_DMASR, DMASR_IOC_IRQ);

    // Cache invalidate RX
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, len);

    get_precise_time(&t_end);

    XTime delta_ticks = t_end - t_start;
    *out_time_us = ticks_to_us(delta_ticks);

    double sec = (double)delta_ticks / (double)COUNTS_PER_SECOND;
    *out_mbps  = ((double)len * 8.0) / (sec * 1000000.0);
    return 0;
}

// ----------------------------------------------------------------------------
// Official Xilinx BSP Throughput Benchmark
// ----------------------------------------------------------------------------
static int benchmark_xilinx_driver_throughput(u32 len, double *out_time_us, double *out_mbps)
{
    XTime t_start, t_end;
    uint32_t timeout;

    // Cache flush TX
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, len);

    get_precise_time(&t_start);

    // Official Xilinx Driver API calls
    XAxiDma_SimpleTransfer(&AxiDmaInstance, (UINTPTR)RxBuffer, len, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_SimpleTransfer(&AxiDmaInstance, (UINTPTR)TxBuffer, len, XAXIDMA_DMA_TO_DEVICE);

    // Wait completion with timeout
    timeout = 10000000;
    while (XAxiDma_Busy(&AxiDmaInstance, XAXIDMA_DMA_TO_DEVICE)) {
        if (--timeout == 0) {
            xil_printf("\n\r[ERROR] Xilinx MM2S timeout at len = %u!\n\r", (unsigned int)len);
            return -1;
        }
    }

    timeout = 10000000;
    while (XAxiDma_Busy(&AxiDmaInstance, XAXIDMA_DEVICE_TO_DMA)) {
        if (--timeout == 0) {
            xil_printf("\n\r[ERROR] Xilinx S2MM timeout at len = %u!\n\r", (unsigned int)len);
            return -1;
        }
    }

    // Cache invalidate RX
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, len);

    get_precise_time(&t_end);

    XTime delta_ticks = t_end - t_start;
    *out_time_us = ticks_to_us(delta_ticks);

    double sec = (double)delta_ticks / (double)COUNTS_PER_SECOND;
    *out_mbps  = ((double)len * 8.0) / (sec * 1000000.0);
    return 0;
}

int main(void)
{
    u8 key[16] = {0};

    // Initialize test pattern
    for (int i = 0; i < MAX_STREAM_BYTES; i++) {
        TxBuffer[i] = (u8)(i & 0xFF);
    }
    memset(RxBuffer, 0x00, MAX_STREAM_BYTES);

    xil_printf("\n\r*********************************************************************************\n\r");
    xil_printf("     AES-128 BURST STREAMING & THROUGHPUT SCALABILITY BENCHMARK (75 MHz PL)      \n\r");
    xil_printf("*********************************************************************************\n\r");

    // Initialize Hardware & Core
    dma_init();
    aes_set_key(key);

    XAxiDma_Config *CfgPtr = XAxiDma_LookupConfig(DMA_DEV_ID);
    if (!CfgPtr) {
        xil_printf("[FATAL] XAxiDma_LookupConfig failed!\n\r");
        return -1;
    }
    XAxiDma_CfgInitialize(&AxiDmaInstance, CfgPtr);
    XAxiDma_IntrDisable(&AxiDmaInstance, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_IntrDisable(&AxiDmaInstance, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DMA_TO_DEVICE);

    // Warm-up custom DMA engine with RS = 1
    dma_write(MM2S_DMACR, DMACR_RS);
    dma_write(S2MM_DMACR, DMACR_RS);
    while (dma_read(MM2S_DMASR) & DMASR_HALTED);
    while (dma_read(S2MM_DMASR) & DMASR_HALTED);

    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    printf("\n\r=================================================================================\n\r");
    printf(" %-10s | %-8s | %-24s | %-24s \n\r", "Bytes", "Blocks", "Custom Driver (Mbps)", "Xilinx BSP (Mbps)");
    printf("=================================================================================\n\r");

    for (int i = 0; i < num_tests; i++) {
        u32 len = test_sizes[i];
        u32 blocks = len / 16;
        double cust_us = 0.0, cust_mbps = 0.0;
        double xil_us = 0.0,  xil_mbps = 0.0;

        // Custom Driver
        int st1 = benchmark_custom_driver_throughput(len, &cust_us, &cust_mbps);

        // Xilinx Driver
        int st2 = benchmark_xilinx_driver_throughput(len, &xil_us, &xil_mbps);

        if (st1 == 0 && st2 == 0) {
            printf(" %-10u | %-8u | %8.2f Mbps (%5.3f Gbps) | %8.2f Mbps (%5.3f Gbps)\n\r",
                   (unsigned int)len, (unsigned int)blocks,
                   cust_mbps, cust_mbps / 1000.0,
                   xil_mbps,  xil_mbps / 1000.0);
        } else {
            printf(" %-10u | %-8u | TRANSFER FAILED         | TRANSFER FAILED         \n\r",
                   (unsigned int)len, (unsigned int)blocks);
        }
    }
    printf("=================================================================================\n\r");
    printf(" Physical AXI HP0 Bus Theoretical Maximum: 4800.00 Mbps (4.800 Gbps @ 75 MHz / 64-bit)\n\r");
    printf(" AES-128 Hardware Pipeline Theoretical Limit: 9600.00 Mbps (9.600 Gbps @ 75 MHz / 128-bit)\n\r");
    printf("=================================================================================\n\r");

    return 0;
}
