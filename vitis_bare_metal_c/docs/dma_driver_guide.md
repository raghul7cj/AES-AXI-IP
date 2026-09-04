# AXI DMA Direct Register-Level Driver Guide

This guide breaks down every function, hardware register, and bit manipulation used in the custom register-level AXI DMA driver for the AES-128 cryptographic SoC.

---

## 1. Hardware Memory Map & Architecture

From the Vivado Block Design:
- **Base Address of AXI DMA (`S_AXI_LITE`)**: `0x40400000`
- **Base Address of AES IP (`s_axi`)**: `0x40000000`
- **Data Ports**: Connected to Zynq PS7 `S_AXI_HP0` via `smartconnect_0` (accesses DDR RAM `0x00000000` - `0x1FFFFFFF`).
- **Operating Mode**: Direct Register Mode / Simple DMA (`C_INCLUDE_SG = 0`).

```
Control Plane:
CPU (ARM Cortex-A9) ---> M_AXI_GP0 ---> axi_interconnect_0 ---> AXI DMA (0x40400000)

Data Plane:
DDR (TxBuffer) ---> HP0 ---> AXI DMA MM2S ---> DWC_0 ---> AES IP (s00_axis)
AES IP (m00_axis) ---> DWC_1 ---> AXI DMA S2MM ---> HP0 ---> DDR (RxBuffer)
```

---

## 2. The 8 Core Hardware Registers

AXI DMA in Direct Register Mode is managed by 8 registers:

| Channel | Register Name | Offset | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **MM2S (TX)** | `MM2S_DMACR` | `0x00` | R/W | Control: Run/Stop, Reset |
| | `MM2S_DMASR` | `0x04` | R/W (W1C)| Status: Halted, Idle, Interrupt On Complete, Errors |
| | `MM2S_SA`    | `0x18` | R/W | Source Address (Lower 32 bits of DDR source buffer) |
| | `MM2S_LENGTH`| `0x28` | R/W | Transfer Length in bytes (**Writing triggers TX**) |
| **S2MM (RX)** | `S2MM_DMACR` | `0x30` | R/W | Control: Run/Stop, Reset |
| | `S2MM_DMASR` | `0x34` | R/W (W1C)| Status: Halted, Idle, Interrupt On Complete, Errors |
| | `S2MM_DA`    | `0x48` | R/W | Destination Address (Lower 32 bits of DDR target buffer) |
| | `S2MM_LENGTH`| `0x58` | R/W | Transfer Length in bytes (**Writing triggers RX**) |

---

## 3. Function Breakdown

---

### Function 1: `dma_init(void)`

#### **Purpose**
Brings both the Transmit (MM2S) and Receive (S2MM) channels out of unknown FPGA power-up states, executes a clean hardware soft reset, clears residual interrupt flags, and puts both channels into the **RUN** state.

#### **Implementation**
```c
int dma_init(void)
{
    xil_printf("[DMA] Initializing Register-Level DMA @ 0x%08X...\n\r", (u32)DMA_BASE);

    // Step 1: Soft Reset both channels
    dma_write(MM2S_DMACR, DMACR_RESET);
    dma_write(S2MM_DMACR, DMACR_RESET);

    // Step 2: Poll until reset completes (DMACR_RESET auto-clears to 0)
    while (dma_read(MM2S_DMACR) & DMACR_RESET);
    while (dma_read(S2MM_DMACR) & DMACR_RESET);

    // Step 3: Clear any pending status/interrupt flags (W1C: Write-1-to-Clear)
    dma_write(MM2S_DMASR, DMASR_IOC_IRQ | DMASR_ERR_MASK);
    dma_write(S2MM_DMASR, DMASR_IOC_IRQ | DMASR_ERR_MASK);

    // Step 4: Start both channels by setting Run/Stop (RS = 1)
    dma_write(MM2S_DMACR, DMACR_RS);
    dma_write(S2MM_DMACR, DMACR_RS);

    // Step 5: Wait until channels exit the Halted state (HALTED bit drops to 0)
    while (dma_read(MM2S_DMASR) & DMASR_HALTED);
    while (dma_read(S2MM_DMASR) & DMASR_HALTED);

    xil_printf("[DMA] Initialization complete. Both channels running and ready.\n\r");
    return 0;
}
```

#### **Step-by-Step Deep Dive**

1. **Step 1 — Asserting Soft Reset (`DMACR_RESET = 1 << 2`)**:
   - Setting bit 2 of `DMACR` forces the internal DMA state machines, pointers, and stream FIFOs into an immediate reset state.
   - All internal buffers are flushed and DMA bus engines are quiesced.

2. **Step 2 — Polling for Reset Completion**:
   - `DMACR_RESET` is self-clearing in hardware.
   - Once the internal logic finishes resetting registers and FIFOs, the hardware automatically resets bit 2 back to `0`.
   - `while (dma_read(MM2S_DMACR) & DMACR_RESET);` spins until the hardware confirms it is ready.

3. **Step 3 — Clearing Status Flags (The W1C Rule)**:
   - Status registers in hardware devices like AXI DMA are **W1C (Write-1-to-Clear)**.
   - Writing `0` to a bit leaves it unchanged.
   - Writing `1` clears the flag.
   - `DMASR_IOC_IRQ` is bit 12 (`0x1000`).
   - `DMASR_ERR_MASK` is bits 4, 5, 6 (`0x70`).
   - Writing `DMASR_IOC_IRQ | DMASR_ERR_MASK` (`0x1070`) ensures no stale completion or error flags linger before our test starts.

4. **Step 4 — Setting Run/Stop (`DMACR_RS = 1 << 0`)**:
   - In AXI DMA, `RS = 1` starts the channel clocking and enables transfer processing.
   - If `RS = 0`, writing to `LENGTH` has **zero effect** and will be ignored!

5. **Step 5 — Waiting for Halted Bit to Clear**:
   - `DMASR_HALTED` is bit 0 of the status register.
   - After setting `RS = 1`, there is a minor latency of a few clock cycles before the channel transitions out of the Halted state into the Running state.
   - Checking `while (dma_read(...) & DMASR_HALTED);` guarantees that the channel is actively running before we attempt our first data transfer.

---

*(Upcoming functions will be added as we implement them!)*

---

### Function 2: `dma_s2mm_start(dst_addr, length)`
#### **Purpose**
Arms the S2MM (Receive) DMA channel to accept encrypted data from the AES core stream and store it in DDR RAM.

```c
static inline void dma_s2mm_start(UINTPTR dst_addr, u32 length)
{
    dma_write(S2MM_DA, (u32)dst_addr);
    dma_write(S2MM_LENGTH, length);  // Writing length initiates the RX engine
}
```
* **Hardware Trigger**: Writing to `S2MM_LENGTH` arms the internal receiver. It must always be executed **before** `MM2S` starts transmitting.

---

### Function 3: `dma_mm2s_start(src_addr, length)`
#### **Purpose**
Initiates transmission of plaintext data from DDR RAM through the `M_AXIS_MM2S` stream to the AES core.

```c
static inline void dma_mm2s_start(UINTPTR src_addr, u32 length)
{
    dma_write(MM2S_SA, (u32)src_addr);
    dma_write(MM2S_LENGTH, length);  // Writing length starts the TX stream
}
```
* **Hardware Trigger**: Writing to `MM2S_LENGTH` begins fetching data from DDR across HP0 into the stream.

---

### Function 4: `dma_mm2s_busy()` and `dma_s2mm_busy()`
#### **Purpose**
Inspects Bit 1 (`DMASR_IDLE`) of the Status Register.
```c
static inline int dma_mm2s_busy(void)
{
    return !(dma_read(MM2S_DMASR) & DMASR_IDLE);
}

static inline int dma_s2mm_busy(void)
{
    return !(dma_read(S2MM_DMASR) & DMASR_IDLE);
}
```
* **Hardware Meaning**:
  - `DMASR_IDLE == 1`: No transfer in progress.
  - `DMASR_IDLE == 0`: Actively transferring data.

---

### Function 5: `dma_wait_completion(void)`
#### **Purpose**
Synchronizes CPU execution with the DMA hardware engines, checking for bus errors, protecting against hardware pipeline deadlocks via timeout counters, and acknowledging the transfer complete flag.

```c
int dma_wait_completion(void)
{
    int timeout;

    // 1. Wait for MM2S (TX) transfer to complete with timeout protection
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
    // Verify and clear the IOC flag (Write-1-to-Clear)
    if (dma_read(MM2S_DMASR) & DMASR_IOC_IRQ) {
        dma_write(MM2S_DMASR, DMASR_IOC_IRQ);
    }

    // 2. Wait for S2MM (RX) transfer to complete with timeout protection
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
    // Verify and clear the IOC flag (Write-1-to-Clear)
    if (dma_read(S2MM_DMASR) & DMASR_IOC_IRQ) {
        dma_write(S2MM_DMASR, DMASR_IOC_IRQ);
    }

    return 0;
}
```
