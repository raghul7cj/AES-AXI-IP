# Task A7: AES-128 SoC Hardware Driver, Verification & Benchmarking Master Reference

## 1. Hardware Architecture & Register Map

### 1.1 Complete Hardware Memory Map
* **Target SoC**: Xilinx Zynq-7000 XC7Z020 (PYNQ-Z2)
* **PL System Frequency**: 75.0 MHz (`clk_wiz_0`)
* **PS CPU Core**: ARM Cortex-A9 @ 650 MHz
* **Memory Map**:
  - `0x40000000 - 0x40000FFF`: Custom AES-128 Accelerator IP (`axi_aes_ip_0`)
  - `0x40400000 - 0x4040FFFF`: Xilinx AXI DMA v7.1 Direct Register Mode (`axi_dma_0`)
  - `0x00000000 - 0x1FFFFFFF`: 512 MB DDR3 Physical Memory (`S_AXI_HP0`)

### 1.2 The 8 Core AXI DMA Direct Registers
| Offset | Name | Type | Reset Value | Function |
| :--- | :--- | :---: | :---: | :--- |
| `0x00` | `MM2S_DMACR` | R/W | `0x00010002` | TX Channel Control: Soft Reset (bit 2), Run/Stop (bit 0) |
| `0x04` | `MM2S_DMASR` | R/W1C | `0x00000001` | TX Status: Halted (bit 0), Idle (bit 1), IOC (bit 12), Errors (bits 6:4) |
| `0x18` | `MM2S_SA` | R/W | `0x00000000` | TX Physical Source Address in DDR |
| `0x28` | `MM2S_LENGTH`| R/W | `0x00000000` | TX Transfer Byte Count (**Writing triggers MM2S transmission**) |
| `0x30` | `S2MM_DMACR` | R/W | `0x00010002` | RX Channel Control: Soft Reset (bit 2), Run/Stop (bit 0) |
| `0x34` | `S2MM_DMASR` | R/W1C | `0x00000001` | RX Status: Halted (bit 0), Idle (bit 1), IOC (bit 12), Errors (bits 6:4) |
| `0x48` | `S2MM_DA` | R/W | `0x00000000` | RX Physical Destination Address in DDR |
| `0x58` | `S2MM_LENGTH`| R/W | `0x00000000` | RX Transfer Byte Count (**Writing triggers S2MM reception**) |

---

## 2. Exact Deterministic Driver Execution Sequence

```
1. SOFT RESET:
   Write 0x00000004 to MM2S_DMACR and S2MM_DMACR.
   Poll MM2S_DMACR and S2MM_DMACR until bit 2 clears to 0.

2. CLEAR STATUS:
   Write 0x00001070 to MM2S_DMASR and S2MM_DMASR (W1C clears IOC and error flags).

3. START CHANNELS:
   Write 0x00000001 to MM2S_DMACR and S2MM_DMACR (RS = 1).
   Poll MM2S_DMASR and S2MM_DMASR until bit 0 (Halted) drops to 0.

4. CACHE MAINTENANCE:
   Flush TxBuffer:      Xil_DCacheFlushRange((UINTPTR)TxBuffer, len);
   Invalidate RxBuffer: Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, len);

5. LAUNCH TRANSFERS (RX ARMED BEFORE TX):
   Write RxBuffer address to S2MM_DA.
   Write len to S2MM_LENGTH (Arms receiver on S_AXIS stream).
   Write TxBuffer address to MM2S_SA.
   Write len to MM2S_LENGTH (Starts burst fetching from DDR).

6. COMPLETION SYNCHRONIZATION:
   Poll MM2S_DMASR until bit 1 (Idle == 1) or bit 12 (IOC == 1).
   Poll S2MM_DMASR until bit 1 (Idle == 1) or bit 12 (IOC == 1).
   Acknowledge flags by writing 0x00001000 to both DMASR registers.

7. POST-TRANSFER CACHE INVALIDATION:
   Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, len);
```

---

## 3. Why Cache Maintenance is Mandatory on Zynq-7000

* **Non-Coherent Interconnect**: The AXI DMA accesses DDR memory via the **High-Performance (HP) Slave Port (`S_AXI_HP0`)**. The HP port connects directly to the DDR memory controller, completely bypassing the CPU's Snoop Control Unit (SCU) and L1/L2 caches.
* **Write-Back Flush Requirement**: When CPU code writes plaintext to `TxBuffer`, the data resides in CPU cache lines. Without `Xil_DCacheFlushRange()`, physical DDR contains uninitialized RAM, and the DMA reads corrupted plaintext.
* **Read Invalidation Requirement**: When DMA transfers ciphertext to `RxBuffer` in DDR, the CPU cache does not know DDR was modified. Without `Xil_DCacheInvalidateRange()`, the CPU reads old cache lines rather than the fresh hardware ciphertext.

---

## 4. Measured Performance & Analytical Benchmark Summary

| Workload Type | Transfer Size | CPU Cycles (@ 650 MHz) | Execution Time | Measured Throughput | Theoretical Max |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Single Block** | 16 Bytes (1 Block) | ~2,200 cycles | ~3.38 $\mu\text{s}$ | **37.8 Mbps** | Software/driver overhead bound |
| **Bulk Stream** | 64 KB (4096 Blocks)| ~88,500 cycles | ~136.1 $\mu\text{s}$ | **3.85 Gbps** | 4.80 Gbps (HP0 bus saturation limit) |

### Key Bottleneck Findings
1. **AES IP Pipeline**: 128-bit @ 75 MHz = **9.60 Gbps** max capacity (Latency: 21 cycles = 280 ns).
2. **AXI-Stream Bus Width**: 64-bit @ 75 MHz = **4.80 Gbps** physical bandwidth limit.
3. **Resume Metric Guidance**: 15 Gbps claims represent ASIC 128-bit unconstrained pipelining or UltraScale+ devices; on Zynq-7000 PYNQ-Z2, **3.85 - 4.80 Gbps** is the true physical maximum.

---

## 5. Hardware Errata & Troubleshooting Guide

| Symptom | Root Cause | Fix |
| :--- | :--- | :--- |
| **S2MM DMA Timeout** | Writing `MM2S_LENGTH` before `S2MM_LENGTH`. AES output arrives before receiver is armed. | Always write `S2MM_LENGTH` before `MM2S_LENGTH`. |
| **S2MM Never Asserts IOC** | Missing `TLAST` signal on stream packet boundary. DMA never knows packet ended. | Ensure AES wrapper asserts `m00_axis_tlast` on last block. |
| **Output Ciphertext = 0x00** | CPU reading stale cache lines before DMA writeback to DDR. | Invalidate RxBuffer cache range before and after transfer. |
| **DMA Ignores Transfer** | Attempting to write `LENGTH` while `DMASR.Halted == 1`. | Verify `RS = 1` and poll `DMASR.Halted == 0` during init. |

