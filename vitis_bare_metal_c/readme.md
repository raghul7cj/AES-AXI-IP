# AES-128 SoC DMA Driver & Bare-Metal Benchmarking Suite

[![Platform: PYNQ-Z2](https://img.shields.io/badge/Platform-TUL_PYNQ--Z2-blue.svg)](https://www.xilinx.com/products/silicon-devices/soc/zynq-7000.html)
[![Target SoC: Zynq-7020](https://img.shields.io/badge/SoC-XC7Z020CLG400--1-orange.svg)]()
[![Core: ARM Cortex-A9](https://img.shields.io/badge/Core-Dual_ARM_Cortex--A9_%40_650MHz-green.svg)]()
[![Environment: Vitis 2022.2](https://img.shields.io/badge/Environment-Vitis_Bare--Metal_C-red.svg)]()

> **Repository Subdirectory:** [`vitis_bare_metal_c`](https://github.com/raghul7cj/AES-AXI-IP/tree/embedded_exploration/vitis_bare_metal_c)  
> **Author:** RAGHUL CJ (`iec2023047@iiita.ac.in`) — IIIT Allahabad  
> **Reports & Documentation:** [Executive Performance Report (HTML)](docs/aes_dma_performance_report.html) | [Granular Latency Specification](docs/GRANULAR_LATENCY_SPECIFICATION.md) | [Final Technical Report](docs/A7_FINAL_TECHNICAL_DOCUMENTATION.md)

---

## 📌 Overview

This directory contains the **embedded bare-metal C driver and profiling suite** for an AES-128 hardware accelerator on the **Xilinx Zynq-7000 SoC (PYNQ-Z2)**.

The software architecture implements a **custom direct-register MMIO driver** designed to replace the standard Xilinx Standalone BSP driver (`xaxidma.h`), eliminating multi-layered function call overhead, descriptor validation, and ring-pointer bookkeeping for low-latency cryptographic transactions.

### Key Capabilities
- **Direct-Register Control:** Direct MMIO register access for AXI DMA engine initialization, channel arming, status polling, and Write-1-to-Clear (W1C) interrupt acknowledgment.
- **Cache Coherency Management:** Explicit L1/L2 data cache maintenance (`Xil_DCacheFlushRange` for TX buffers, `Xil_DCacheInvalidateRange` for RX buffers) ensuring correct DDR coherency over the non-coherent **AXI_HP0** port.
- **Granular Latency Profiling:** Checkpoint timing architecture isolating software dispatch latency from hardware interconnect and accelerator execution using the ARM Global Timer with memory barriers (`dsb sy` + `isb`).
- **Throughput Scalability Sweep:** Automated benchmark measuring sustained data rates from 16 Bytes to 8 Kilobytes ($N = 200$ iterations).

---

## 🏗️ Hardware-Software Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PROCESSING SYSTEM (PS) — ARM Cortex-A9               │
│                                                                        │
│   ┌────────────────────────┐              ┌────────────────────────┐   │
│   │ Custom C Driver        │              │   L1/L2 Data Cache     │   │
│   │ (axi_dma_reg.h)        │              │ (DCacheFlush / Inval)  │   │
│   └───────────┬────────────┘              └───────────┬────────────┘   │
│               │ M_AXI_GP0 (32-bit AXI-Lite MMIO)      │                │
│               ▼                                       ▼                │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                    DDR3 Controller (512 MB)                    │   │
│   │       TxBuffer (Plaintext)    │    RxBuffer (Ciphertext)       │   │
│   └───────────────────────────────┼────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ 64-bit AXI_HP0 (Bidirectional)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 PROGRAMMABLE LOGIC (PL Fabric @ 75.0 MHz)              │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │             AXI DMA Engine (Direct Register Mode)              │   │
│   │     Base: 0x40400000 • MM2S (TX Master) | S2MM (RX Master)     │   │
│   └───────────┬───────────────────────────────────▲────────────────┘   │
│               │ 64-bit AXIS                       │ 64-bit AXIS        │
│               ▼                                   │                    │
│   ┌───────────────────────────────────────────────┴────────────────┐   │
│   │        AES-128 Pipelined Accelerator (Base: 0x40000000)        │   │
│   │          Key Expansion & Encryption Engine @ 75 MHz            │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Memory Map & Low-Level Register Interface

### 1. AXI DMA Registers (Base: `0x40400000`)
Simple DMA / Direct Register Mode (`C_INCLUDE_SG = 0`, `C_SG_LENGTH_WIDTH = 14`).

| Offset | Register | Description | Functional Operation |
| :--- | :--- | :--- | :--- |
| `0x00` | `MM2S_DMACR` | TX Control | Write `0x04` for Soft Reset; write `0x01` to set `RS = 1` (Run) |
| `0x04` | `MM2S_DMASR` | TX Status | Bit 0: `Halted`, Bit 1: `Idle`, Bit 12: `IOC_Irq` (W1C), Bits 4-6: `Errors` |
| `0x18` | `MM2S_SA` | TX Source Addr | Set 32-bit DDR physical address of `TxBuffer` |
| `0x28` | `MM2S_LENGTH` | TX Length | Write byte count ($1\text{ to }16,383$) $\to$ **triggers MM2S transmit** |
| `0x30` | `S2MM_DMACR` | RX Control | Write `0x04` for Soft Reset; write `0x01` to set `RS = 1` (Run) |
| `0x34` | `S2MM_DMASR` | RX Status | Bit 0: `Halted`, Bit 1: `Idle`, Bit 12: `IOC_Irq` (W1C), Bits 4-6: `Errors` |
| `0x48` | `S2MM_DA` | RX Dest Addr | Set 32-bit DDR physical address of `RxBuffer` |
| `0x58` | `S2MM_LENGTH` | RX Length | Write byte count ($1\text{ to }16,383$) $\to$ **arms S2MM receive** |

### 2. AES Accelerator Control Registers (Base: `0x40000000`)

| Offset | Register | Type | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | `REG_KEY_0` | W | 128-bit Key Word 0 (Bits [127:96]) |
| `0x04` | `REG_KEY_1` | W | 128-bit Key Word 1 (Bits [95:64]) |
| `0x08` | `REG_KEY_2` | W | 128-bit Key Word 2 (Bits [63:32]) |
| `0x0C` | `REG_KEY_3` | W | 128-bit Key Word 3 (Bits [31:0]) |
| `0x10` | `REG_MODE` | W | Mode configuration (`0x01`: Encrypt) |
| `0x14` | `REG_TRIG` | W | Pulse bit 0 (`0x1` then `0x0`) to trigger hardware key expansion |
| `0x18` | `REG_STAT` | R | Bit 1: Key Ready (`1`), Bit 0: Engine Busy |

---

## ⚡ Empirical Performance & Benchmark Results

All figures were captured on physical silicon (PYNQ-Z2, PS @ 650 MHz, PL @ 75 MHz) averaged across **$N = 200$ runs** with instruction/data barrier synchronization.

### 1. Granular Stage Latency Breakdown (Single 16-Byte Block)

| Profiling Stage | Custom Direct Driver | Xilinx Standalone BSP | Delta / Observation |
| :--- | :---: | :---: | :--- |
| **Stage 1: Pre-TX Cache Flush** | $0.283\text{ }\mu\text{s}$ | $0.281\text{ }\mu\text{s}$ | Hardware L1/L2 clean duration |
| **Stage 2: Driver Arming / Dispatch** | $\mathbf{1.529\text{ }\mu\text{s}}$ | $\mathbf{3.540\text{ }\mu\text{s}}$ | **$2.32\times$ faster** (direct MMIO vs. BSP validation layers) |
| **Stage 3: MM2S HP0 Read Latency** | $0.803\text{ }\mu\text{s}$ | $0.875\text{ }\mu\text{s}$ | DDR burst read & stream width conversion |
| **Stage 4: S2MM Tail Latency** | $1.096\text{ }\mu\text{s}$ | $0.893\text{ }\mu\text{s}$ | Stream downsize & DDR writeback completion |
| **Stage 5: Post-RX Cache Invalidate** | $0.964\text{ }\mu\text{s}$ | $0.274\text{ }\mu\text{s}$ | Hardware L1/L2 invalidate range duration |
| **Total Hardware Silicon Path** | $1.899\text{ }\mu\text{s}$ | $1.768\text{ }\mu\text{s}$ | HP0 bus transfer & AES pipeline execution |
| **Total End-to-End Latency** | $\mathbf{4.675\text{ }\mu\text{s}}$ | $\mathbf{5.862\text{ }\mu\text{s}}$ | **Saves $1.187\text{ }\mu\text{s}$ transaction overhead** |

### 2. Throughput Scalability Sweep (16 Bytes to 8 Kilobytes)

| Transfer Size | AES Blocks | Custom Driver Rate | Xilinx BSP Rate | Operational Bottleneck |
| :---: | :---: | :---: | :---: | :--- |
| **16 B** | 1 | **23.65 Mbps** | 21.44 Mbps | Software Arming Overhead Bound |
| **64 B** | 4 | **95.30 Mbps** | 86.40 Mbps | Arming Cost Amortization |
| **256 B** | 16 | **334.30 Mbps** | 308.01 Mbps | Pipelined Stream Transition |
| **512 B** | 32 | **565.27 Mbps** | 534.83 Mbps | Pipelined Streaming |
| **1024 B** | 64 | **907.12 Mbps** | 836.18 Mbps | Near-Gigabit Streaming |
| **2048 B** | 128 | **1227.76 Mbps** (1.23 Gbps) | 1182.50 Mbps (1.18 Gbps) | High-Efficiency DDR Bursting |
| **4096 B** | 256 | **1496.15 Mbps** (1.50 Gbps) | 1494.26 Mbps (1.49 Gbps) | Interconnect Bandwidth Saturated |
| **8192 B** | 512 | **1707.21 Mbps** ($\mathbf{1.71\text{ Gbps}}$) | 1707.76 Mbps ($\mathbf{1.71\text{ Gbps}}$) | **HP0 Memory Interconnect Ceiling** |

### 3. Bus Utilization Analysis
- **Theoretical Single-Port Limit:** 64-bit @ $75\text{ MHz} = 4.800\text{ Gbps}$.
- **Bidirectional Half-Duplex Bound:** MM2S and S2MM contend for DDR controller arbitration on shared HP0 $\to 2.400\text{ Gbps}$.
- **Achieved Sustainable Throughput:** $\mathbf{1.707\text{ Gbps}}$ represents **$\mathbf{71.2\%}$ practical bus efficiency**, with the remainder occupied by DDR row turnarounds, width conversion, and cache management.

---

## 📁 Source File Directory

| File | Description |
| :--- | :--- |
| [`axi_dma_reg.h`](axi_dma_reg.h) | **Core direct-register driver header**: Macros, register offsets, bitfield masks, inline MMIO helpers, status dump, and timeout-protected transfer routines |
| [`task_a2_raw_control_path.c`](task_a2_raw_control_path.c) | **Task A2**: Low-level control path validation (soft reset, W1C interrupt clearing, Run/Stop state transitions) |
| [`task_a3_first_transfer.c`](task_a3_first_transfer.c) | **Task A3**: First single-block direct DMA transfer and ciphertext verification |
| [`task_a4_full_regression.c`](task_a4_full_regression.c) | **Task A4**: Comprehensive regression suite with NIST Known Answer Tests (KAT), all-zeros/ones vectors, and backpressure bursts |
| [`task_a6_granular_latency.c`](task_a6_granular_latency.c) | **Task A6 (Part 1)**: High-resolution 6-stage PMU/Global Timer latency benchmark with standard deviation ($N = 200$) |
| [`task_a6_throughput_benchmark.c`](task_a6_throughput_benchmark.c) | **Task A6 (Part 2)**: Throughput scaling sweep across payload sizes (16B to 8KB) comparing custom driver vs Xilinx BSP |
| [`bare_metal_driver_original_backup.c`](bare_metal_driver_original_backup.c) | Reference Xilinx Standalone BSP driver implementation used for cross-validation |
| [`docs/`](docs/) | Complete technical specifications, hardware register reference, and executive reports |

---

## 🧪 Verification Test Matrix

All tests execute on bare-metal and output real-time validation over UART:

1. **NIST Known Answer Test (FIPS 197 KAT):**
   - **Key:** `2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c`
   - **Plaintext:** `6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a`
   - **Ciphertext Output:** `3a d7 7b b4 0d 7a 36 60 a8 9e ca f3 24 66 ef 97` $\to$ **`[PASS]`**
2. **All-Zeros Key / All-Zeros Plaintext:**
   - **Output:** `66 e9 4b d4 ef 8a 2c 3b 88 4c fa 59 ca 34 2b 2e` $\to$ **`[PASS]`**
3. **Corner Test Patterns:** All-Ones (`0xFF`), Alternating bits (`0xAA`, `0x55`), and Sequential ramps $\to$ **`[PASS]`**
4. **Multi-Block Stream Test:** 4 consecutive 16-byte blocks ($64\text{ Bytes}$) in one continuous DMA stream $\to$ **`[PASS]`**

---

## 🚀 How to Build & Run in Vitis 2022.2

### 1. Hardware Connection
1. Connect the **PYNQ-Z2** board to your workstation using a Micro-USB cable (PROG/UART port).
2. Ensure boot jumpers are set to **JTAG mode**.
3. Open a serial terminal (e.g., TeraTerm, PuTTY, or Vitis Serial Terminal) at **115200 baud, 8N1, no flow control**.

### 2. Vitis Application Setup
1. Launch **Vitis 2022.2** and select this directory as the workspace.
2. Create a new **Application Project** targeting the exported platform `.xsa`.
3. Add `axi_dma_reg.h` and the target C file (e.g., `task_a6_granular_latency.c` or `task_a6_throughput_benchmark.c`) to `src/`.
4. Build the application (`Ctrl + B`).

### 3. Execution
1. Right-click the application project $\to$ **Run As $\to$ Launch on Hardware (Single Application Debug)**.
2. The bitstream is programmed, the ARM core is initialized, and benchmark results will stream to your serial terminal.

---

## 📜 Key Architectural Takeaways

1. **Direct MMIO Efficiency:** Eliminating vendor abstraction layers cuts CPU arming overhead by **$56.8\%$ ($1.53\text{ }\mu\text{s}$ vs $3.54\text{ }\mu\text{s}$)**.
2. **Offload Break-Even Threshold:** Hardware DMA offload surpasses CPU software AES execution above **$\sim 200\text{ Bytes}$**, scaling to a **$6.6\times$ throughput speedup** at 8 KB.
3. **Driver Sequencing Rule:** S2MM (sink) must be armed before MM2S (source) is triggered to guarantee that the receive FIFO and DDR write channel are active before data starts streaming.
