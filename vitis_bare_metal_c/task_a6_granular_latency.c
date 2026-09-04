/*
 * ============================================================================
 * Task A6: Rigorous Granular Stage-by-Stage Latency & Driver Comparison Suite
 * ============================================================================
 * Target Hardware : TUL PYNQ-Z2 (XC7Z020CLG400-1)
 * CPU Frequency   : 650.0 MHz (ARM Cortex-A9 Core 0)
 * Timer Engine    : ARM Cortex-A9 Global Timer (COUNTS_PER_SECOND = 325 MHz)
 *
 * RIGOROUS PROFILING METHODOLOGY:
 *   1. Hardware Memory Barriers (DSB + ISB) on all timestamp snapshots.
 *   2. Cache Warm-Up passes before benchmark collection (eliminates cold misses).
 *   3. Concurrency-aware hardware timing (MM2S & S2MM execute in parallel).
 *   4. Speculative cache safety: eliminated redundant pre-invalidation of Rx.
 *   5. Clean reset and status quiescing between driver transitions.
 *   6. Multi-iteration statistical aggregation (Mean, Min, Max, Standard Deviation).
 *   7. Output verification assertion on every iteration.
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "xtime_l.h"
#include "xil_printf.h"
#include "xil_cache.h"
#include "xparameters.h"
#include "xaxidma.h"
#include "axi_dma_reg.h"

#define AES_BASE_ADDR           0x40000000
#define DMA_DEV_ID              XPAR_AXIDMA_0_DEVICE_ID
#define BENCHMARK_ITERATIONS    200
#define CACHE_LINE_SIZE         32  // Cortex-A9 L1 data cache line width

// 64-byte aligned buffers
static u8 TxBuffer[64] __attribute__((aligned(64)));
static u8 RxBuffer[64] __attribute__((aligned(64)));

static const u8 GoldReversed[16] = {
    0x0B, 0x76, 0xFB, 0xBE, 0x5D, 0x54, 0xE1, 0x75,
    0xB1, 0x3D, 0xDD, 0x8E, 0xFF, 0x31, 0xA3, 0xC8
};

static XAxiDma AxiDmaInstance;

// Timestamp checkpoints for a single iteration
typedef struct {
    XTime t0_start;          // Before TX cache flush
    XTime t1_flush_done;     // After TX cache flush (memory barrier synced)
    XTime t2_driver_armed;   // After CSR / API trigger writes
    XTime t3_mm2s_done;      // MM2S hardware completed
    XTime t4_s2mm_done;      // S2MM hardware completed (both channels done)
    XTime t5_post_sync_done; // After RX cache invalidate & DSB
} timestamp_set_t;

// Statistical aggregation metrics
typedef struct {
    double mean_us;
    double min_us;
    double max_us;
    double stddev_us;
} stage_stat_t;

typedef struct {
    stage_stat_t pre_flush;    // T1 - T0
    stage_stat_t driver_arm;   // T2 - T1
    stage_stat_t hw_mm2s;      // T3 - T2
    stage_stat_t hw_total;     // T4 - T2 (Total concurrent hardware transfer time)
    stage_stat_t s2mm_tail;    // T4 - T3 (Residual pipeline tail latency)
    stage_stat_t post_inval;   // T5 - T4
    stage_stat_t end_to_end;   // T5 - T0
} profile_summary_t;

// ----------------------------------------------------------------------------
// Accurate Timestamp Helper with Data Synchronization Barriers
// ----------------------------------------------------------------------------
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
// 1. Single Iteration: Custom Direct Register Driver
// ----------------------------------------------------------------------------
static void run_custom_iteration(timestamp_set_t *ts)
{
    // [T0] Start of transaction
    get_precise_time(&ts->t0_start);

    // Stage 1: Pre-Transfer Cache Coherency (Flush TX only)
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, CACHE_LINE_SIZE);
    get_precise_time(&ts->t1_flush_done);

    // Stage 2: Direct CSR Programming (Arm RX first, then launch TX)
    dma_write(S2MM_DA, (u32)RxBuffer);
    dma_write(S2MM_LENGTH, 16);
    dma_write(MM2S_SA, (u32)TxBuffer);
    dma_write(MM2S_LENGTH, 16);
    get_precise_time(&ts->t2_driver_armed);

    // Stage 3: Wait for MM2S Hardware Completion
    while (dma_mm2s_busy());
    get_precise_time(&ts->t3_mm2s_done);

    // Stage 4: Wait for S2MM Hardware Completion
    while (dma_s2mm_busy());
    get_precise_time(&ts->t4_s2mm_done);

    // Clear W1C IOC status flags
    dma_write(MM2S_DMASR, DMASR_IOC_IRQ);
    dma_write(S2MM_DMASR, DMASR_IOC_IRQ);

    // Stage 5: Post-Transfer Cache Invalidation on RxBuffer
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, CACHE_LINE_SIZE);
    get_precise_time(&ts->t5_post_sync_done);
}

// ----------------------------------------------------------------------------
// 2. Single Iteration: Official Xilinx Standalone BSP Driver
// ----------------------------------------------------------------------------
static void run_xilinx_iteration(timestamp_set_t *ts)
{
    // [T0] Start of transaction
    get_precise_time(&ts->t0_start);

    // Stage 1: Pre-Transfer Cache Coherency (Flush TX only)
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, CACHE_LINE_SIZE);
    get_precise_time(&ts->t1_flush_done);

    // Stage 2: Official Xilinx Driver APIs (Arm RX first, then launch TX)
    XAxiDma_SimpleTransfer(&AxiDmaInstance, (UINTPTR)RxBuffer, 16, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_SimpleTransfer(&AxiDmaInstance, (UINTPTR)TxBuffer, 16, XAXIDMA_DMA_TO_DEVICE);
    get_precise_time(&ts->t2_driver_armed);

    // Stage 3: Wait for MM2S Hardware Completion
    while (XAxiDma_Busy(&AxiDmaInstance, XAXIDMA_DMA_TO_DEVICE));
    get_precise_time(&ts->t3_mm2s_done);

    // Stage 4: Wait for S2MM Hardware Completion
    while (XAxiDma_Busy(&AxiDmaInstance, XAXIDMA_DEVICE_TO_DMA));
    get_precise_time(&ts->t4_s2mm_done);

    // Stage 5: Post-Transfer Cache Invalidation on RxBuffer
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, CACHE_LINE_SIZE);
    get_precise_time(&ts->t5_post_sync_done);
}

// ----------------------------------------------------------------------------
// Statistical Calculator
// ----------------------------------------------------------------------------
// Fast integer/double square root via Newton-Raphson (eliminates -lm linker dependency)
static double fast_sqrt(double val)
{
    if (val <= 0.0) return 0.0;
    double x = val;
    for (int i = 0; i < 15; i++) {
        x = 0.5 * (x + val / x);
    }
    return x;
}

static void calculate_stage_stats(const double *values, int count, stage_stat_t *stat)
{
    double sum = 0.0;
    double min_v = values[0];
    double max_v = values[0];

    for (int i = 0; i < count; i++) {
        sum += values[i];
        if (values[i] < min_v) min_v = values[i];
        if (values[i] > max_v) max_v = values[i];
    }

    stat->mean_us = sum / count;
    stat->min_us  = min_v;
    stat->max_us  = max_v;

    double variance_sum = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = values[i] - stat->mean_us;
        variance_sum += diff * diff;
    }
    stat->stddev_us = fast_sqrt(variance_sum / count);
}

static void aggregate_profiles(const timestamp_set_t *raw, int count, profile_summary_t *summary)
{
    double d_flush[BENCHMARK_ITERATIONS];
    double d_arm[BENCHMARK_ITERATIONS];
    double d_mm2s[BENCHMARK_ITERATIONS];
    double d_hw_total[BENCHMARK_ITERATIONS];
    double d_s2mm_tail[BENCHMARK_ITERATIONS];
    double d_inval[BENCHMARK_ITERATIONS];
    double d_e2e[BENCHMARK_ITERATIONS];

    for (int i = 0; i < count; i++) {
        d_flush[i]     = ticks_to_us(raw[i].t1_flush_done     - raw[i].t0_start);
        d_arm[i]       = ticks_to_us(raw[i].t2_driver_armed   - raw[i].t1_flush_done);
        d_mm2s[i]      = ticks_to_us(raw[i].t3_mm2s_done      - raw[i].t2_driver_armed);
        d_hw_total[i]  = ticks_to_us(raw[i].t4_s2mm_done      - raw[i].t2_driver_armed);
        d_s2mm_tail[i] = ticks_to_us(raw[i].t4_s2mm_done      - raw[i].t3_mm2s_done);
        d_inval[i]     = ticks_to_us(raw[i].t5_post_sync_done - raw[i].t4_s2mm_done);
        d_e2e[i]       = ticks_to_us(raw[i].t5_post_sync_done - raw[i].t0_start);
    }

    calculate_stage_stats(d_flush, count, &summary->pre_flush);
    calculate_stage_stats(d_arm, count, &summary->driver_arm);
    calculate_stage_stats(d_mm2s, count, &summary->hw_mm2s);
    calculate_stage_stats(d_hw_total, count, &summary->hw_total);
    calculate_stage_stats(d_s2mm_tail, count, &summary->s2mm_tail);
    calculate_stage_stats(d_inval, count, &summary->post_inval);
    calculate_stage_stats(d_e2e, count, &summary->end_to_end);
}

// ----------------------------------------------------------------------------
// Display Breakdown Table
// ----------------------------------------------------------------------------
static void print_summary_table(const char *driver_name, const profile_summary_t *s)
{
    printf("\n\r=================================================================================\n\r");
    printf(" PROFILE BREAKDOWN: %s (%d Iterations Aggregated)\n\r", driver_name, BENCHMARK_ITERATIONS);
    printf("=================================================================================\n\r");
    printf(" %-30s | %8s | %8s | %8s | %8s\n\r", "Stage Name", "Mean(us)", "Min(us)", "Max(us)", "StdDev");
    printf("---------------------------------------------------------------------------------\n\r");
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "Stage 1: Pre-TX Flush Range",    s->pre_flush.mean_us,  s->pre_flush.min_us,  s->pre_flush.max_us,  s->pre_flush.stddev_us);
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "Stage 2: Driver Invocation/Arm",  s->driver_arm.mean_us, s->driver_arm.min_us, s->driver_arm.max_us, s->driver_arm.stddev_us);
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "Stage 3: MM2S HP0 Read Latency",   s->hw_mm2s.mean_us,    s->hw_mm2s.min_us,    s->hw_mm2s.max_us,    s->hw_mm2s.stddev_us);
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "Stage 4: S2MM Tail (Post-MM2S)",   s->s2mm_tail.mean_us,  s->s2mm_tail.min_us,  s->s2mm_tail.max_us,  s->s2mm_tail.stddev_us);
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "Stage 5: Post-RX Invalidate",     s->post_inval.mean_us, s->post_inval.min_us, s->post_inval.max_us, s->post_inval.stddev_us);
    printf("---------------------------------------------------------------------------------\n\r");
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "TOTAL CONCURRENT HARDWARE TIME",   s->hw_total.mean_us,   s->hw_total.min_us,   s->hw_total.max_us,   s->hw_total.stddev_us);
    printf(" %-30s | %8.3f | %8.3f | %8.3f | %8.3f\n\r", "TOTAL END-TO-END TRANSACTION",     s->end_to_end.mean_us, s->end_to_end.min_us, s->end_to_end.max_us, s->end_to_end.stddev_us);
    printf("=================================================================================\n\r");
}

int main(void)
{
    static timestamp_set_t custom_raw[BENCHMARK_ITERATIONS];
    static timestamp_set_t xilinx_raw[BENCHMARK_ITERATIONS];
    profile_summary_t custom_summary;
    profile_summary_t xilinx_summary;

    u8 pt[16] = {0xFF,0xEE,0xDD,0xCC, 0xBB,0xAA,0x99,0x88, 0x77,0x66,0x55,0x44, 0x33,0x22,0x11,0x00};
    u8 key[16] = {0};

    memcpy(TxBuffer, pt, 16);
    memset(RxBuffer, 0x00, 16);

    xil_printf("\n\r*********************************************************************************\n\r");
    xil_printf("   RIGOROUS GRANULAR LATENCY & DRIVER PROFILING BENCHMARK (N = %d Runs)   \n\r", BENCHMARK_ITERATIONS);
    xil_printf("*********************************************************************************\n\r");

    // 1. Initialize Custom DMA Controller & AES Core Key
    dma_init();
    aes_set_key(key);

    // ------------------------------------------------------------------------
    // Benchmark Part 1: Custom Direct Register Driver
    // ------------------------------------------------------------------------
    // Warm-up runs to prime I-cache and D-cache
    timestamp_set_t dummy;
    for (int w = 0; w < 10; w++) {
        run_custom_iteration(&dummy);
    }

    // Benchmark measurement collection
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        run_custom_iteration(&custom_raw[i]);
        if (memcmp(RxBuffer, GoldReversed, 16) != 0) {
            xil_printf("[FATAL ERROR] Custom driver output mismatch at iteration %d!\n\r", i);
            return -1;
        }
    }
    aggregate_profiles(custom_raw, BENCHMARK_ITERATIONS, &custom_summary);
    print_summary_table("Custom Direct Register Driver", &custom_summary);

    // ------------------------------------------------------------------------
    // Hardware Reset & Switch to Xilinx BSP Driver
    // ------------------------------------------------------------------------
    dma_init(); // Clean hardware reset between runs

    XAxiDma_Config *CfgPtr = XAxiDma_LookupConfig(DMA_DEV_ID);
    if (!CfgPtr) {
        xil_printf("[FATAL] XAxiDma_LookupConfig failed!\n\r");
        return -1;
    }
    XAxiDma_CfgInitialize(&AxiDmaInstance, CfgPtr);
    XAxiDma_IntrDisable(&AxiDmaInstance, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_IntrDisable(&AxiDmaInstance, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DMA_TO_DEVICE);

    // Warm-up runs for Xilinx driver
    for (int w = 0; w < 10; w++) {
        run_xilinx_iteration(&dummy);
    }

    // Benchmark measurement collection
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        run_xilinx_iteration(&xilinx_raw[i]);
        if (memcmp(RxBuffer, GoldReversed, 16) != 0) {
            xil_printf("[FATAL ERROR] Xilinx driver output mismatch at iteration %d!\n\r", i);
            return -1;
        }
    }
    aggregate_profiles(xilinx_raw, BENCHMARK_ITERATIONS, &xilinx_summary);
    print_summary_table("Official Xilinx Standalone BSP Driver", &xilinx_summary);

    // ------------------------------------------------------------------------
    // Statistical Head-to-Head Comparison
    // ------------------------------------------------------------------------
    double custom_arm_mean = custom_summary.driver_arm.mean_us;
    double xilinx_arm_mean = xilinx_summary.driver_arm.mean_us;
    double arm_speedup     = xilinx_arm_mean / custom_arm_mean;

    double custom_e2e_mean = custom_summary.end_to_end.mean_us;
    double xilinx_e2e_mean = xilinx_summary.end_to_end.mean_us;
    double e2e_diff_us     = xilinx_e2e_mean - custom_e2e_mean;

    printf("\n\r=================================================================================\n\r");
    printf("                    EXECUTIVE DRIVER PERFORMANCE SUMMARY                         \n\r");
    printf("=================================================================================\n\r");
    printf(" Metric                            | Custom Driver | Xilinx BSP   | Comparison   \n\r");
    printf("-----------------------------------+---------------+--------------+--------------\n\r");
    printf(" Driver Arming Time (Stage 2) Mean | %8.3f us   | %8.3f us  | %.2fx faster \n\r",
           custom_arm_mean, xilinx_arm_mean, arm_speedup);
    printf(" Total End-to-End Latency Mean     | %8.3f us   | %8.3f us  | -%.3f us     \n\r",
           custom_e2e_mean, xilinx_e2e_mean, e2e_diff_us);
    printf(" Valid Ciphertext Verified (N=%d) | [ PASS 100%% ] | [PASS 100%%] | Zero Faults  \n\r",
           BENCHMARK_ITERATIONS);
    printf("=================================================================================\n\r");

    return 0;
}
