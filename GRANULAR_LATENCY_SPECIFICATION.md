# Granular Latency Benchmarking Specification: Stage-by-Stage Profiling

## 1. Overview & Objective
To obtain deep visibility into the exact latency composition of a single 16-byte AES-128 cryptographic transfer, we profile the end-to-end transaction at microsecond and CPU-tick resolution using the ARM Global Timer (`xtime_l.h`).

We instrument **6 granular hardware checkpoints** to isolate:
1. **Cache Maintenance Overhead** (Flush & Invalidate)
2. **Driver Programming Overhead** (Register setup time: Custom Direct Register vs Xilinx BSP Driver)
3. **Hardware Transmission & Bus Latency** (MM2S DDR-to-Stream read across HP0)
4. **Hardware Pipeline Latency** (Width conversion + AES-128 21-cycle encryption + Width conversion)
5. **Hardware Reception & Bus Latency** (S2MM Stream-to-DDR write across HP0)
6. **Post-transfer Cache Sync Overhead** (Invalidate range before CPU read)

---

## 2. Granular Stage Checkpoint Architecture

```
Timeline Checkpoints:
  [T0] Start
   |
   |--- Stage 1: Pre-Transfer Cache Coherency (Flush TX, Invalidate RX)
   |
  [T1] Cache Ready
   |
   |--- Stage 2: Driver Invocation & CSR Programming (Set DA, Length, SA, Length)
   |
  [T2] Hardware Triggered (MM2S & S2MM Fired)
   |
   |--- Stage 3: MM2S TX Burst over HP0 + AES Pipeline (21 cycles @ 75 MHz)
   |
  [T3] MM2S Completed (MM2S_DMASR.Idle == 1 / IOC asserted)
   |
   |--- Stage 4: S2MM RX Burst over HP0 + DDR Write
   |
  [T4] S2MM Completed (S2MM_DMASR.Idle == 1 / IOC asserted)
   |
   |--- Stage 5: Post-Transfer Cache Invalidation (RxBuffer in DDR -> Cache reload)
   |
  [T5] Buffer Synced & CPU Ready
```

---

## 3. Mathematical Calculations & Timing Resolution

* **Timer Mechanism**: ARM Cortex-A9 Global Timer (`XTime_GetTime`)
* **Clock Rate**: `COUNTS_PER_SECOND = CPU_FREQ / 2 = 325,000,000 Hz` (on 650 MHz Zynq-7000)
* **Resolution**: 1 Tick $\approx 3.077\text{ ns}$

### Granular Stage Metrics
| Metric / Stage | Formula | Target Measurement |
| :--- | :--- | :--- |
| **Stage 1: Pre-Cache** | $(T_1 - T_0)$ | Time to push TX cache lines to DDR & invalidate RX |
| **Stage 2: Driver Setup** | $(T_2 - T_1)$ | **Custom Driver vs Xilinx Driver comparison point** |
| **Stage 3: MM2S Bus + IP** | $(T_3 - T_2)$ | DDR fetch + stream upsize + 21-cycle AES core |
| **Stage 4: S2MM Writeback** | $(T_4 - T_3)$ | Downsize + S2MM HP0 burst write to DDR |
| **Stage 5: Post-Cache** | $(T_5 - T_4)$ | Invalidate RX cache range for CPU read |
| **Total Hardware Latency** | $(T_4 - T_2)$ | Pure hardware domain latency |
| **Total End-to-End Latency**| $(T_5 - T_0)$ | Complete round-trip application latency |

---

## 4. Expected Comparative Insights
1. **Driver Invocation Overhead ($T_2 - T_1$)**:
   - *Custom Register Driver*: ~4 inline `Xil_Out32` instructions ($\sim 0.05 - 0.1\ \mu\text{s}$).
   - *Xilinx BSP Driver (`XAxiDma_SimpleTransfer`)*: Validation branches, pointer dereferences, ring checks ($\sim 0.5 - 1.2\ \mu\text{s}$).
2. **Hardware Pipeline Bound ($T_4 - T_2$)**:
   - AES core takes $21\text{ cycles} @ 75\text{ MHz} = 280\text{ ns}$.
   - HP0 burst read/write + width converters $\approx 0.5 - 0.8\ \mu\text{s}$.

