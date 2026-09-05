# Hardware-Accelerated AES-128 Engine & Direct-Register SoC DMA Driver

[![Platform: PYNQ-Z2](https://img.shields.io/badge/Platform-TUL_PYNQ--Z2-blue.svg)](https://www.xilinx.com/products/silicon-devices/soc/zynq-7000.html)
[![Target SoC: Zynq-7020](https://img.shields.io/badge/SoC-XC7Z020CLG400--1-orange.svg)]()
[![Standard: FIPS 197](https://img.shields.io/badge/Standard-FIPS_197_AES--128-green.svg)]()
[![Toolchain: Vivado / Vitis 2022.2](https://img.shields.io/badge/Toolchain-Vivado_%2F_Vitis_2022.2-red.svg)]()

> **Repository Branch:** [`embedded_exploration`](https://github.com/raghul7cj/AES-AXI-IP/tree/embedded_exploration/vitis_bare_metal_c)  
> **Author:** RAGHUL CJ (`iec2023047@iiita.ac.in`) — IIIT Allahabad  
> **Documentation:** [Performance Characterization Report (HTML)](docs/aes_dma_performance_report.html) | [Granular Latency Specification](docs/GRANULAR_LATENCY_SPECIFICATION.md) | [Final Technical Report](docs/A7_FINAL_TECHNICAL_DOCUMENTATION.md)

---

## 📌 Project Overview

This repository contains a high-performance **AES-128 Cryptographic Accelerator Engine** implemented in Verilog and integrated onto the **Xilinx Zynq-7000 SoC (PYNQ-Z2)**, paired with a custom **low-overhead bare-metal C direct-register driver**.

The architecture decouples control signaling and high-throughput data streaming:
- **Control Plane:** AXI4-Lite slave interface for on-the-fly 128-bit key configuration and hardware expansion control.
- **Data Streaming Path:** AXI4-Stream master/slave interfaces linked to an AXI DMA engine operating over a 64-bit high-performance AXI port (**AXI_HP0**) directly to DDR3 memory.
- **Driver Architecture:** A custom register-level bare-metal driver bypassing high-latency vendor BSP abstractions to minimize software CPU arming overhead and maximize streaming throughput.

---

## ⚙️ Technical Specifications

### Hardware Coprocessor (PL Fabric @ 75.0 MHz)
- **Algorithm:** AES-128 Encryption (NIST FIPS 197 Standard).
- **Architecture:** 128-bit fully synchronous pipelined datapath (10 encryption rounds).
- **Core Pipeline Latency:** 21 clock cycles ($280\text{ ns}$ at $75\text{ MHz}$).
- **Peak Core Datapath Ceiling:** $128\text{ bits} \times 75\text{ MHz} = \mathbf{9.600\text{ Gbps}}$ ($1,200\text{ MB/s}$).
- **Streaming Width:** 128-bit AXI4-Stream with asynchronous width converters (64-bit $\leftrightarrow$ 128-bit).
- **Flow Control:** Hardware backpressure handling via `TVALID`/`TREADY` handshaking with gated valid signals.
- **Verification:** 100% pass rate against NIST Known Answer Tests (KAT) and custom corner vectors.

### Processing System (PS @ 650 MHz Cortex-A9)
- **Timer Subsystem:** ARM Global Timer ($325\text{ MHz}$, resolution $\sim 3.07\text{ ns}$) bounded by `dsb sy` / `isb` serialization barriers.
- **Memory Subsystem:** 512 MB DDR3, 32 KB L1 Data Cache, 512 KB L2 Cache.
- **DMA Interconnect:** 64-bit AXI HP0 slave port (theoretical single-direction ceiling $4.800\text{ Gbps}$).

---

## 📊 Hardware Register Maps

### 1. AES-128 IP Register Map (Base: `0x40000000` via AXI-Lite GP0)

The AES IP is memory-mapped to the Zynq Processing System via AXI4-Lite.

| Offset | Name | Type | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | `REG_KEY_0` | W | Key Word 0 (Bits [127:96]) — MSB |
| `0x04` | `REG_KEY_1` | W | Key Word 1 (Bits [95:64]) |
| `0x08` | `REG_KEY_2` | W | Key Word 2 (Bits [63:32]) |
| `0x0C` | `REG_KEY_3` | W | Key Word 3 (Bits [31:0]) — LSB |
| `0x10` | `REG_MODE` | W | Mode Select: `0x01`: ENC, `0x10`: DEC, `0x11`: BOTH |
| `0x14` | `REG_TRIG` | W | Pulse bit 0 (`0x1` then `0x0`) to trigger hardware key expansion |
| `0x18` | `REG_STAT` | R | Status: **Bit 1**: Key Expansion Ready (`1`), **Bit 0**: Engine Busy |

### 2. AXI DMA Direct Register Map (Base: `0x40400000` via AXI-Lite GP0)

Configured in Direct Register (Simple) DMA Mode (`C_INCLUDE_SG = 0`, `C_SG_LENGTH_WIDTH = 14`).

| Offset | Register Name | Description | Key Bitfields |
| :--- | :--- | :--- | :--- |
| `0x00` | `MM2S_DMACR` | TX Control Register | Bit 0: `RS` (Run/Stop), Bit 2: `Reset` |
| `0x04` | `MM2S_DMASR` | TX Status Register | Bit 0: `Halted`, Bit 1: `Idle`, Bit 12: `IOC_Irq` (W1C), Bits 4-6: `Errors` |
| `0x18` | `MM2S_SA` | TX Source Physical Address | 32-bit DDR physical address (`TxBuffer`) |
| `0x28` | `MM2S_LENGTH` | TX Transfer Length | Byte count ($1\text{ to }16,383$); **writing triggers MM2S DMA** |
| `0x30` | `S2MM_DMACR` | RX Control Register | Bit 0: `RS` (Run/Stop), Bit 2: `Reset` |
| `0x34` | `S2MM_DMASR` | RX Status Register | Bit 0: `Halted`, Bit 1: `Idle`, Bit 12: `IOC_Irq` (W1C), Bits 4-6: `Errors` |
| `0x48` | `S2MM_DA` | RX Destination Physical Address | 32-bit DDR physical address (`RxBuffer`) |
| `0x58` | `S2MM_LENGTH` | RX Transfer Length | Byte count ($1\text{ to }16,383$); **writing arms S2MM DMA** |

---

## 🏗️ System Architecture & Dataflow

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PROCESSING SYSTEM (PS) — ARM Cortex-A9               │
│                                                                        │
│   ┌────────────────────────┐              ┌────────────────────────┐   │
│   │   Custom C Driver      │              │    L1/L2 Data Cache    │   │
│   │  (Direct MMIO Access)  │              │ (Flush TX / Inval RX)  │   │
│   └───────────┬────────────┘              └───────────┬────────────┘   │
│               │ M_AXI_GP0                             │                │
│               │ (32-bit AXI-Lite)                     │                │
│               ▼                                       ▼                │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                    DDR3 Controller (512 MB)                    │   │
│   │       TxBuffer (Plaintext)    │    RxBuffer (Ciphertext)       │   │
│   └───────────────────────────────┼────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ 64-bit AXI_HP0 (Bidirectional)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 PROGRAMMABLE LOGIC (PL Fabric @ 75 MHz)                │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                        AXI DMA Engine                          │   │
│   │    MM2S (DDR Read Master)      │   S2MM (DDR Write Master)     │   │
│   └───────────┬────────────────────┴──────────────▲────────────────┘   │
│               │ 64-bit AXIS                       │ 64-bit AXIS        │
│               ▼                                   │                    │
│   ┌────────────────────────┐              ┌───────┴────────────────┐   │
│   │ axis_dwidth_converter  │              │ axis_dwidth_converter  │   │
│   │      (64b -> 128b)     │              │     (128b -> 64b)      │   │
│   └───────────┬────────────┘              └───────▲────────────────┘   │
│               │ 128-bit AXIS                      │ 128-bit AXIS       │
│               ▼                                   │                    │
│   ┌───────────────────────────────────────────────┴────────────────┐   │
│   │             AES-128 Pipelined Core (FIPS 197)                  │   │
│   │       10-Round Encryption Datapath • Latency = 21 cycles       │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Empirical Performance Characterization

All benchmarks were collected on physical PYNQ-Z2 silicon over **$N = 200$ iterations** using hardware timers with barrier synchronization (`dsb` + `isb`).

### 1. Granular Stage Latency Breakdown (16-Byte Single Block)

| Pipeline Stage | Custom Driver | Xilinx Standalone BSP | Delta / Insight |
| :--- | :---: | :---: | :--- |
| **Stage 1: Pre-TX Cache Flush** | $0.283\text{ }\mu\text{s}$ | $0.281\text{ }\mu\text{s}$ | L1/L2 clean range duration |
| **Stage 2: Driver Arming / Dispatch** | $\mathbf{1.529\text{ }\mu\text{s}}$ | $\mathbf{3.540\text{ }\mu\text{s}}$ | **$2.32\times$ faster** (direct MMIO vs. BSP validation layers) |
| **Stage 3: MM2S HP0 Read Latency** | $0.803\text{ }\mu\text{s}$ | $0.875\text{ }\mu\text{s}$ | DDR burst read & 64b $\to$ 128b conversion |
| **Stage 4: S2MM Tail Latency** | $1.096\text{ }\mu\text{s}$ | $0.893\text{ }\mu\text{s}$ | 128b $\to$ 64b conversion & DDR burst writeback |
| **Stage 5: Post-RX Cache Invalidate** | $0.964\text{ }\mu\text{s}$ | $0.274\text{ }\mu\text{s}$ | L1/L2 cache invalidate range operation |
| **Total Hardware Execution Time** | $1.899\text{ }\mu\text{s}$ | $1.768\text{ }\mu\text{s}$ | Pure silicon path (HP0 transfers + AES pipeline) |
| **Total End-to-End Latency** | $\mathbf{4.675\text{ }\mu\text{s}}$ | $\mathbf{5.862\text{ }\mu\text{s}}$ | **Saves $1.187\text{ }\mu\text{s}$ per transaction** |

### 2. Throughput Scaling Across Payload Sizes (16 B to 8 KB)

| Buffer Size | Blocks | Custom Driver Throughput | Xilinx BSP Throughput | Operational Regime |
| :---: | :---: | :---: | :---: | :--- |
| **16 Bytes** | 1 | **23.65 Mbps** (0.024 Gbps) | 21.44 Mbps (0.021 Gbps) | Software Overhead Bound |
| **64 Bytes** | 4 | **95.30 Mbps** (0.095 Gbps) | 86.40 Mbps (0.086 Gbps) | Amortizing Arming Cost |
| **256 Bytes** | 16 | **334.30 Mbps** (0.334 Gbps) | 308.01 Mbps (0.308 Gbps) | Pipelined Streaming Transition |
| **512 Bytes** | 32 | **565.27 Mbps** (0.565 Gbps) | 534.83 Mbps (0.535 Gbps) | Active Pipeline Saturation |
| **1024 Bytes** | 64 | **907.12 Mbps** (0.907 Gbps) | 836.18 Mbps (0.836 Gbps) | Near-Gigabit Streaming |
| **2048 Bytes** | 128 | **1227.76 Mbps** (1.23 Gbps) | 1182.50 Mbps (1.18 Gbps) | High-Efficiency DDR Bursting |
| **4096 Bytes** | 256 | **1496.15 Mbps** (1.50 Gbps) | 1494.26 Mbps (1.49 Gbps) | Approaching Bus Saturation |
| **8192 Bytes** | 512 | **1707.21 Mbps** ($\mathbf{1.71\text{ Gbps}}$) | 1707.76 Mbps ($\mathbf{1.71\text{ Gbps}}$) | **AXI HP0 Memory Saturated** |

### 3. Interconnect Efficiency Analysis
- **Theoretical AXI_HP0 Bus Limit:** 64-bit @ $75\text{ MHz} = 4.800\text{ Gbps}$.
- **Half-Duplex Contention:** Both MM2S and S2MM channels share the single HP0 slave port, placing the practical bidirectional limit at $2.400\text{ Gbps}$.
- **Achieved Sustained Throughput:** $\mathbf{1.707\text{ Gbps}}$ represents **$\mathbf{71.2\%}$ practical bus utilization efficiency**, with the remainder consumed by DDR row-activation overhead, width-converter conversion, and cache management.

---

## 📁 Repository Structure

```
.
├── axi_dma_reg.h                       # Low-level direct-register DMA driver header
├── task_a2_raw_control_path.c          # Task A2: DMA soft-reset, W1C & Run/Stop validation
├── task_a3_first_transfer.c            # Task A3: Single-block end-to-end DMA transfer
├── task_a4_full_regression.c           # Task A4: NIST KAT validation & backpressure suite
├── task_a6_granular_latency.c          # Task A6: 6-stage PMU/Timer latency profiling (N=200)
├── task_a6_throughput_benchmark.c      # Task A6: Payload sweep benchmark (16B to 8KB)
├── bare_metal_driver_original_backup.c # Reference Xilinx Standalone BSP driver implementation
├── README.md                           # Project technical overview
│
├── docs/                               # Comprehensive Technical Documentation
│   ├── aes_dma_performance_report.html # Standalone executive performance report
│   ├── A7_FINAL_TECHNICAL_DOCUMENTATION.md # Final engineering report with measured data
│   ├── AXI_DMA_REGISTER_SPECIFICATION.md  # Detailed hardware register reference
│   ├── GRANULAR_LATENCY_SPECIFICATION.md # Checkpoint profiling methodology (T0–T5)
│   ├── THROUGHPUT_BENCHMARK_PLAN.md      # Scaling analysis & bus theoretical models
│   └── SIL_HARDWARE_EMULATION_GUIDE.md   # Hardware emulation and debugging guide
│
└── xsa_unzipped/                       # Hardware Hand-Off Export
    ├── aes_dma_loop.hwh                # Vivado hardware architecture description
    └── aes_dma_loop.bda                # Address map bindings
```

---

## 🧪 Verification & Test Suite

The test suite validates hardware and driver correctness against multiple test scenarios:

1. **NIST Known Answer Test (KAT):**
   - **Key:** `2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c`
   - **Plaintext:** `6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a`
   - **Ciphertext:** `3a d7 7b b4 0d 7a 36 60 a8 9e ca f3 24 66 ef 97` $\to$ **PASS**
2. **All-Zeros Pattern:** Key $= 0$, Plain $= 0 \implies \text{Cipher} = \text{66e94bd4ef8a2c3b884cfa59ca342b2e}$ $\to$ **PASS**
3. **Corner Patterns:** All-Ones (`0xFF`), Alternating bits (`0xAA`, `0x55`), Sequential byte ramps.
4. **Multi-Block Stream Backpressure:** 4-block consecutive burst ($64\text{ Bytes}$) testing `s00_axis_tready` stalling behavior $\to$ **PASS**.

---

## 🚀 How to Build & Run on Hardware

### 1. Prerequisites
- **Hardware:** TUL PYNQ-Z2 (XC7Z020) connected via Micro-USB (JTAG/UART).
- **Tools:** Xilinx Vitis 2022.2 / Vivado 2022.2.
- **Serial Console:** 115200 baud, 8N1, no flow control.

### 2. Running Bare-Metal Benchmarks in Vitis
1. Launch Vitis 2022.2 and open the workspace containing this repository.
2. Create an **Application Project** targeting the exported hardware platform (`.xsa`).
3. Add `axi_dma_reg.h` and the desired task source file (e.g., `task_a6_granular_latency.c` or `task_a6_throughput_benchmark.c`) to the project's `src/` directory.
4. Build the project (`Ctrl + B`).
5. Open Vivado Hardware Manager or Vitis, program the FPGA bitstream, and select **Run As $\to$ Launch on Hardware (Single Application Debug)**.
6. Observe real-time UART output showing timing statistics, throughput figures, and verification results.

---

## 📜 Key Architectural Insights

1. **Software Overhead Amortization Threshold:**
   - For transfers under **$\sim 200\text{ Bytes}$**, CPU-side execution can rival hardware DMA due to fixed cache flush, invalidate, and MMIO setup costs.
   - For transfers above **$200\text{ Bytes}$**, hardware acceleration delivers up to **$6.6\times$ throughput speedup** over CPU execution while fully offloading the Cortex-A9 core.
2. **Direct Register Driver Advantages:**
   - Direct MMIO access cuts arming overhead by **$56.8\%$ ($1.53\text{ }\mu\text{s}$ vs $3.54\text{ }\mu\text{s}$)** by stripping away dynamic descriptor allocators and multi-layered validity checks.
3. **Sequential Arming Rule:**
   - S2MM (receive channel) must always be armed **before** MM2S (transmit channel) is triggered to ensure the receive sink is ready and avoid AXI stream backpressure stalls.
