# Software-in-the-Loop (SIL) Hardware Emulation & Fault Injection Guide

**Target Domain**: High-Reliability Embedded Firmware & Automotive Systems (Tesla / Autopilot / ECUs)  
**Hardware Platform Under Emulation**: Xilinx Zynq-7000 (Pynq-Z2), AXI DMA (PG021), Custom AES-128 IP  
**Methodology**: Software-in-the-Loop (SIL) Host Simulation & Deterministic Fault Injection (DFI)

---

## 1. Executive Summary: Why Industry Firmware Teams Use SIL

In safety-critical firmware development (such as Tesla vehicles, SpaceX flight systems, and defense electronics), **relying solely on physical hardware is considered an anti-pattern**. 

### The Problem with "Hardware-Only" Testing:
1. **Hardware Scarcity & Bottlenecks**: Silicon and FPGA boards are expensive, shared across teams, and frequently unavailable.
2. **Slow Cycle Times**: Flashing bitstreams, attaching JTAG cables, and setting up oscilloscopes/ILAs turns a 5-second unit test into a 10-minute manual bring-up cycle.
3. **Cannot Test Edge Cases On Demand**: How do you test if your DMA driver handles a DDR slave decode error (`DMASlvErr`) or an AXI-Stream FIFO overflow (`DMAIntErr`) on physical hardware? You cannot easily command silicon to short-circuit or misbehave on demand.

### The Professional Solution: Software-in-the-Loop (SIL)
SIL decouples driver logic from physical silicon. We compile the **exact same driver source code** natively on an x86 Linux development workstation using `gcc`, replacing the low-level bus accessors (`Xil_In32`/`Xil_Out32`) with an **in-memory virtual hardware engine**.

```
+-------------------------------------------------------------------------+
|                  HOST LINUX SYSTEM (x86_64 / GCC)                       |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 PRODUCTION DRIVER LOGIC (Unchanged)               |  |
|  |       dma_init(), dma_s2mm_start(), dma_mm2s_start(),             |  |
|  |       dma_wait_completion(), NIST FIPS-197 Test Harness           |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                      dma_write()   |   dma_read()                       |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |             VIRTUAL HARDWARE EMULATOR (mock_engine.c)             |  |
|  |  * Register Shadow State (MM2S_DMACR, S2MM_DMASR, SA, DA, LEN)    |  |
|  |  * W1C Bitmask Logic & Self-Clearing Reset State Machine           |  |
|  |  * Virtual AES-128 Crypto Engine (Software Reference)             |  |
|  |  * Fault Injection Hooks: FORCE_TIMEOUT, FORCE_BUS_ERROR          |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
+-------------------------------------------------------------------------+
```

---

## 2. Deep-Dive Study Material: Core Systems Concepts

### 2.1 Hardware Abstraction Layer (HAL) & Zero-Cost Abstraction
A well-architected device driver does not hardcode raw memory pointers directly in the business logic. Instead, it accesses hardware through thin, inline access primitives:
```c
// On Physical Zynq Target:
static inline void dma_write(u32 offset, u32 val) { Xil_Out32(DMA_BASE + offset, val); }
static inline u32  dma_read(u32 offset)           { return Xil_In32(DMA_BASE + offset); }

// In Host SIL Emulation:
static inline void dma_write(u32 offset, u32 val) { mock_dma_write(offset, val); }
static inline u32  dma_read(u32 offset)           { return mock_dma_read(offset); }
```
Because these are `static inline`, the compiler resolves them at compile time. On target hardware, it generates zero additional assembly instructions compared to direct MMIO. On host x86, it routes seamlessly into the mock engine.

---

### 2.2 Modeling Hardware Register Semantics in C
Hardware registers do not behave like normal C variables. When building a virtual hardware stub, you must accurately model three hardware behaviors:

1. **Self-Clearing Bits (e.g. `DMACR_RESET`)**:
   - In physical silicon, writing `1` to bit 2 triggers a hardware reset sequence, and the core resets the bit to `0` when ready.
   - *In SIL Mock*: When written with `DMACR_RESET`, the mock engine clears channel FIFOs and state, and immediately clears bit 2 back to `0`.

2. **Side-Effect Triggers (e.g. `MM2S_LENGTH` and `S2MM_LENGTH`)**:
   - In physical silicon, writing the byte count to `LENGTH` is the hardware event that initiates DMA state machine execution.
   - *In SIL Mock*: The mock intercepts writes to offset `0x28` (`MM2S_LENGTH`) and `0x58` (`S2MM_LENGTH`). Once both lengths and addresses are set, the mock triggers the simulated transfer.

3. **Write-1-to-Clear (W1C) Bits (e.g. `DMASR_IOC_IRQ` and `DMASR_ERR_MASK`)**:
   - In physical silicon, writing `1` resets the flag to `0`; writing `0` leaves it unchanged.
   - *In SIL Mock*:
     ```c
     // W1C logic in mock_engine:
     registers[offset] &= ~(value & W1C_MASK);
     ```

---

### 2.3 Deterministic Fault Injection (DFI)
A key question interviewers at Tesla will ask:
> *"How did you verify that your error handling and timeout code actually works?"*

Testing error paths on real hardware is notoriously difficult because you cannot command physical DDR controllers or AXI buses to inject a parity or address decode error.

With SIL, we implement **Fault Injection Control Flags**:
```c
typedef enum {
    FAULT_NONE = 0,
    FAULT_MM2S_SLAVE_ERROR,    // Injects DMASlvErr (Bit 5)
    FAULT_S2MM_DECODE_ERROR,   // Injects DMADecErr (Bit 6)
    FAULT_PIPELINE_STALL,      // Simulates dropped TREADY (Forces Timeout)
    FAULT_MISSING_TLAST        // Simulates incomplete RX burst
} dma_fault_type_t;
```
By setting `mock_inject_fault(FAULT_PIPELINE_STALL);`, we can deterministically prove that our driver's `timeout = 10000000` loop catches the stall, aborts safely, logs `[DMA TIMEOUT]`, and recovers without hanging the system.

---

## 3. Implementation Architecture: The Mock Subsystem

To build this cleanly, we organize the host test environment into three modules:

```
vitis_bare_metal_c/
├── axi_dma_reg.h              <-- Production driver (unmodified)
├── bare_metal_driver.c        <-- Production application testbench
├── sil_test/
│   ├── mock_hw_platform.h    <-- Emulated Xilinx BSP headers (xil_types, xil_io)
│   ├── mock_dma_engine.c     <-- State machine emulator for AXI DMA & AES IP
│   ├── mock_dma_engine.h     <-- Interface and Fault Injection API
│   ├── host_test_runner.c    <-- Main executable for Linux host unit tests
│   └── Makefile              <-- Standard GCC build script
```

### 3.1 Emulating Platform BSP (`mock_hw_platform.h`)
Replaces Xilinx standalone BSP headers so standard Linux `gcc` can compile the code without Xilinx toolchain dependencies:
```c
#ifndef MOCK_HW_PLATFORM_H
#define MOCK_HW_PLATFORM_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uintptr_t UINTPTR;

#define xil_printf printf

// Cache maintenance stubs on x86 (x86 cache is hardware-coherent)
#define Xil_DCacheFlushRange(addr, len)      ((void)0)
#define Xil_DCacheInvalidateRange(addr, len) ((void)0)

#endif
```

---

### 3.2 The Virtual DMA State Machine (`mock_dma_engine.c`)

```c
#include "mock_hw_platform.h"
#include "mock_dma_engine.h"

static u32 dma_regs[64] = {0};
static u32 aes_regs[16] = {0};
static dma_fault_type_t active_fault = FAULT_NONE;

void mock_inject_fault(dma_fault_type_t fault) {
    active_fault = fault;
}

u32 mock_dma_read(u32 offset) {
    u32 index = offset / 4;
    return dma_regs[index];
}

void mock_dma_write(u32 offset, u32 val) {
    u32 index = offset / 4;

    switch (offset) {
        case 0x00: // MM2S_DMACR
            if (val & (1 << 2)) { // Reset requested
                dma_regs[0x04 / 4] |= (1 << 0); // Set Halted
                dma_regs[index] &= ~(1 << 2);   // Auto-clear Reset bit
            }
            if (val & (1 << 0)) { // Run/Stop = 1
                dma_regs[0x04 / 4] &= ~(1 << 0); // Clear Halted
                dma_regs[0x04 / 4] |= (1 << 1);  // Set Idle
            }
            dma_regs[index] = val;
            break;

        case 0x04: // MM2S_DMASR (W1C bits)
            dma_regs[index] &= ~(val & 0x7070); // Clear written W1C bits
            break;

        case 0x28: // MM2S_LENGTH written -> TRIGGERS SIMULATED TRANSFER!
            dma_regs[index] = val;
            execute_simulated_transfer();
            break;

        default:
            dma_regs[index] = val;
            break;
    }
}
```

---

## 4. Test Matrix: What We Validate on Host Before Board Flashing

| Test Case | Objective | Fault Injected | Expected Driver Behavior |
| :--- | :--- | :---: | :--- |
| **TC-01: Nominal Single-Block** | Verify standard 16-byte transfer | `NONE` | Passes NIST KAT vector, `IOC_IRQ` clears, returns `0` |
| **TC-02: Nominal Multi-Block** | Verify 64-byte continuous stream | `NONE` | All 4 blocks match expected ciphertext |
| **TC-03: Pipeline Deadlock** | Validate timeout guard | `FAULT_PIPELINE_STALL` | Aborts after `timeout` expires, returns `-2`, logs stall |
| **TC-04: Bus Error Handling** | Validate `DMASR_ERR_MASK` detection | `FAULT_MM2S_SLAVE_ERROR` | Immediately catches `DMASlvErr`, aborts, returns `-1` |
| **TC-05: Missing TLAST / Underflow**| Validate S2MM receiver guard | `FAULT_MISSING_TLAST` | Receiver times out, returns `-3`, state remains clean |

---

## 5. Staff Engineer Interview Guide: How to Articulate This to Tesla

When interviewing with a Tesla Staff Firmware Engineer, frame your work using **production firmware language**:

### Question: *"How did you verify your DMA driver before hardware bring-up?"*
> **Answer**:  
> *"Because board time was limited, I treated the hardware as an untrusted external dependency. I abstracted the bus layer and built a Software-in-the-Loop (SIL) register emulator in C that models the AXI DMA's control/status state machines, W1C semantics, and self-clearing reset bits.*  
> 
> *This allowed me to do two things before touching physical silicon:  
> 1. Run the full NIST FIPS-197 Known-Answer Test suite in a native Linux unit-test harness.  
> 2. Implement a Deterministic Fault Injection framework to prove that my driver's timeout safety loops and bus error handlers (`DMASlvErr`/`DMADecErr`) actually catch faults and prevent CPU hangs, which is virtually impossible to test on physical silicon on demand."*

### Key Technical Terms to Use:
- **SIL (Software-in-the-Loop)**
- **Deterministic Fault Injection (DFI)**
- **W1C (Write-1-to-Clear) hardware side-effect modeling**
- **Bus error recovery (`SLVERR`, `DECERR`)**
- **Zero-cost HAL abstraction (`static inline` accessors)**
- **ARM Cache Coherency (Clean & Invalidate boundaries)**
