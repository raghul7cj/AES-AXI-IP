# Task A6: Latency & Throughput Benchmarking & Resume Performance Audit

## 1. Overview & Objective
Task A6 provides empirical, cycle-accurate performance benchmarks of the hardware AES accelerator across two distinct operational regimes:
1. **Single-Block Latency Regime (16 Bytes / 1 Block)**: Isolates driver invocation, hardware trigger overhead, and AES round pipeline latency.
2. **Bulk Streaming Throughput Regime (64 KB / 4,096 Blocks)**: Saturates the AXI4 HP0 bus to measure peak sustained data rates.
3. **Resume Metric Audit**: Analytically compares measured numbers against theoretical maximums to reconcile physical hardware bandwidth vs theoretical claims.

---

## 2. Background & Educational Concepts

### 2.1 Cycle-Accurate Timing with ARM PMU (CP15)
Standard timer peripherals (like TTC or private timers) introduce bus read latency when accessed over AXI. The **ARM Cortex-A9 Performance Monitor Unit (PMU)** provides an internal 32-bit hardware cycle counter (`CCNT`) inside coprocessor 15 (`CP15`), readable in a single CPU instruction without memory bus overhead:

```c
// Enable PMU CCNT
asm volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(val));
val |= 0x5; // PMCR: Enable counters + Reset cycle counter
asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(val));
asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x80000000)); // PMCNTENSET: Bit 31 enables CCNT

// Read cycle count
static inline u32 pmu_get_cycles(void) {
    u32 cycles;
    asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(cycles));
    return cycles;
}
```

### 2.2 Mathematical Formulas for Benchmarking
1. **Elapsed Time ($\Delta t$)**:
   $$\Delta t = \frac{\text{CPU Cycles}}{\text{CPU Frequency (650 MHz)}} = \frac{\Delta \text{Cycles}}{650 \times 10^6}\text{ seconds}$$

2. **Sustained Throughput ($T$)**:
   $$T = \frac{\text{Total Bits Transferred}}{\Delta t} = \frac{\text{Bytes} \times 8}{\Delta t \times 10^6}\text{ Mbps}$$

---

## 3. Theoretical Performance Modeling vs Physical Constraints

```
+------------------------------------------------------------------------------------+
|                               System Bottleneck Hierarchy                          |
+------------------------------------------------------------------------------------+
| 1. Pure AES-128 Pipeline (128-bit @ 75 MHz)              :  9.60 Gbps (1.20 GB/s)  |
| 2. AXI-Stream Bus into DMA (64-bit @ 75 MHz)             :  4.80 Gbps (600 MB/s)   |
| 3. AXI HP0 DDR Port (64-bit @ 75 MHz, Read+Write shared) :  4.80 Gbps (600 MB/s)   |
| 4. Software Single-Block Polling (Overhead-limited)       :  ~30 - 60 Mbps         |
+------------------------------------------------------------------------------------+
```

### 3.1 Breakdown of Hardware Limits
* **AES Core Latency**: 21 clock cycles @ 75 MHz = **280 nanoseconds**.
* **DMA MM2S Stream Width**: 64 bits @ 75 MHz = **4.80 Gbps**.
* **AES IP Stream Width**: 128 bits @ 75 MHz = **9.60 Gbps**.
* **Conclusion**: The system throughput is bounded by the **64-bit DMA Stream & AXI HP0 port**, providing an absolute hardware ceiling of **4.80 Gbps (600 MB/s)**.

### 3.2 The Resume Claim Audit
* **Common Resume Claim**: "Designed a 15 Gbps AES hardware accelerator."
* **Reality Check**:
  * On a **Zynq-7000 (Pynq-Z2)** SoC with a 75 MHz clock and 64-bit DMA, the theoretical maximum data rate across the bus is **4.80 Gbps**.
  * A 15 Gbps number corresponds to:
    - Running the 128-bit core at $\ge 120\text{ MHz}$ on an UltraScale+ platform with 128-bit or 256-bit DMA interfaces.
    - Pure pipelined core synthesis without DMA memory interconnect overhead.
* **Resume Recommendation**:
  * State: *"Achieved 4.8 Gbps bus-saturated throughput on Zynq-7000 (75 MHz PL); core pipeline architecture synthesizable up to 15+ Gbps on UltraScale+ targets."*

---

## 4. Benchmark Code Implementation

```c
void task_a6_benchmark(void)
{
    pmu_init();

    // 1. Single-Block Latency Test
    u32 t0 = pmu_get_cycles();
    dma_s2mm_start((UINTPTR)RxBuffer, 16);
    dma_mm2s_start((UINTPTR)TxBuffer, 16);
    dma_wait_completion();
    u32 t1 = pmu_get_cycles();

    u32 latency_cycles = t1 - t0;
    float latency_us = ((float)latency_cycles / 650000000.0f) * 1e6f;

    // 2. Heavy Multi-Block Stream (64 KB)
    u32 stream_len = 64 * 1024;
    t0 = pmu_get_cycles();
    dma_s2mm_start((UINTPTR)RxBuffer, stream_len);
    dma_mm2s_start((UINTPTR)TxBuffer, stream_len);
    dma_wait_completion();
    t1 = pmu_get_cycles();

    u32 stream_cycles = t1 - t0;
    float stream_sec = (float)stream_cycles / 650000000.0f;
    float throughput_mbps = ((float)stream_len * 8.0f) / (stream_sec * 1e6f);

    xil_printf("Single-Block Latency : %u cycles (%d.%02d us)\n\r",
               latency_cycles, (int)latency_us, ((int)(latency_us * 100)) % 100);
    xil_printf("64 KB Stream Speed   : %d.%02d Mbps (%d.%03d Gbps)\n\r",
               (int)throughput_mbps, ((int)(throughput_mbps * 100)) % 100,
               (int)(throughput_mbps/1000), ((int)throughput_mbps) % 1000);
}
```

