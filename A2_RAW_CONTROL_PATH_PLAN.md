# Task A2: Raw Control Path & DMA State Machine Verification

## 1. Overview & Objective
Task A2 verifies the direct hardware control path of the Xilinx AXI DMA (`axi_dma_0` @ `0x40400000`) on the PYNQ-Z2 board using low-level register accesses (`Xil_In32` / `Xil_Out32`).

**Success Criteria**:
- Software issues a soft reset to both MM2S and S2MM channels.
- Hardware confirms completion by self-clearing `DMACR.Reset`.
- Software transitions both channels to the Run state (`DMACR.RS = 1`).
- Hardware confirms execution by de-asserting `DMASR.Halted` (`Halted = 0`).

---

## 2. Background & Educational Concepts

### 2.1 The Two DMA Channels
1. **MM2S (Memory-to-Stream / TX)**: Reads data from DDR3 RAM via `S_AXI_HP0` and feeds the AES core stream (`s00_axis`).
2. **S2MM (Stream-to-Memory / RX)**: Receives encrypted data from the AES core stream (`m00_axis`) and writes to DDR3 RAM.

### 2.2 The Role of Control & Status Registers
```
   ARM CPU (GP0)                    AXI DMA Controller
         |                                  |
         |--- Xil_Out32(DMACR, Reset=1) --->| (Flushes FIFOs, resets FSMs)
         |                                  |
         |<-- Poll DMACR (Reset==0) --------| (Hardware self-clears Reset)
         |                                  |
         |--- Xil_Out32(DMASR, 0x1070) ---->| (W1C: Clears IOC and Error bits)
         |                                  |
         |--- Xil_Out32(DMACR, RS=1) ------>| (Starts DMA engine clocks)
         |                                  |
         |<-- Poll DMASR (Halted==0) -------| (Engine is now RUNNING & IDLE)
```

### 2.3 The Self-Clearing Reset Bit (`DMACR[2]`)
* Resetting the DMA engine is an asynchronous hardware procedure that purges internal line buffers and synchronizes cross-clock boundaries.
* While reset is executing, bit 2 of `DMACR` stays `1`. When internal logic is stable, hardware forces this bit to `0`. Software must poll this bit before issuing any further commands.

### 2.4 The W1C (Write-1-to-Clear) Rule
* Status registers (`DMASR`) use **W1C**. Writing a `1` clears the respective bit, while writing `0` leaves it untouched.
* Standard bit manipulation rules for CPU RAM (`reg &= ~mask`) do **not** work for hardware W1C registers; performing a read-modify-write will accidentally clear all active flags!

---

## 3. Register Specification for Task A2

| Offset | Register | Bit | Name | Action | Description |
| :--- | :--- | :---: | :--- | :---: | :--- |
| `0x00` / `0x30` | `DMACR` | 2 | `Reset` | Write 1, Poll 0 | Issues soft reset to channel |
| `0x04` / `0x34` | `DMASR` | 12, 6:4 | `IOC_Irq`, `Errors` | Write 1 | Clears lingering flags |
| `0x00` / `0x30` | `DMACR` | 0 | `RS` | Write 1 | Run/Stop control (1 = Run) |
| `0x04` / `0x34` | `DMASR` | 0 | `Halted` | Poll 0 | 0 = Engine running, ready for length |

---

## 4. Verification Sequence & Code Implementation

```c
int task_a2_raw_control_path(void)
{
    // 1. Assert Soft Reset
    Xil_Out32(0x40400000 + 0x00, 0x4); // MM2S Reset
    Xil_Out32(0x40400000 + 0x30, 0x4); // S2MM Reset

    // 2. Poll until Reset completes
    while (Xil_In32(0x40400000 + 0x00) & 0x4);
    while (Xil_In32(0x40400000 + 0x30) & 0x4);

    // 3. Clear status flags (W1C)
    Xil_Out32(0x40400000 + 0x04, 0x1070);
    Xil_Out32(0x40400000 + 0x34, 0x1070);

    // 4. Start channels (RS = 1)
    Xil_Out32(0x40400000 + 0x00, 0x1);
    Xil_Out32(0x40400000 + 0x30, 0x1);

    // 5. Verify Halted bit is cleared to 0
    while (Xil_In32(0x40400000 + 0x04) & 0x1);
    while (Xil_In32(0x40400000 + 0x34) & 0x1);

    xil_printf("[TASK A2] Success: Both DMA channels running (Halted = 0).\n\r");
    return 0;
}
```

