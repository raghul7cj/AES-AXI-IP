# Task A3: First Correct Single-Block Transfer & Cache Coherency

## 1. Overview & Objective
Task A3 executes the first full round-trip cryptographic hardware transfer over AXI DMA:
`DDR (TxBuffer) -> AXI DMA MM2S -> AES IP -> AXI DMA S2MM -> DDR (RxBuffer)`.

**Success Criteria**:
- Correct cache maintenance routines executed before and after DMA transfer.
- Transmit 16 bytes of plaintext; receive 16 bytes of ciphertext.
- Output matches the NIST standard vector bit-for-bit.

---

## 2. Background & Educational Concepts

### 2.1 The Non-Coherent Memory Challenge
The Zynq-7000 architecture connects the PL DMA master to the Processing System via the **HP (High Performance) Slave Ports (`S_AXI_HP0`)**.
- **The Problem**: HP ports bypass the ARM L1 and L2 cache controllers (SCU) and connect straight to the DDR RAM controller.
- **The Hazard**:
  1. If the CPU prepares `TxBuffer`, the data sits dirty in L1/L2 cache. The DMA will read old, stale DDR memory unless the CPU **flushes** the cache line (`Xil_DCacheFlushRange`).
  2. When the DMA writes the result into `RxBuffer`, the DDR memory is updated, but the CPU may have cached stale `0x00` values. The CPU must **invalidate** its cache (`Xil_DCacheInvalidateRange`) to force a fresh read from DDR.

```
       CPU Core (Writes Tx)
               |
        +--------------+
        | L1/L2 Cache  | <--- Dirty lines not yet in DDR!
        +--------------+
               | (Xil_DCacheFlushRange)
               v
        +--------------+
        | DDR3 Memory  | <=== (DMA MM2S reads directly from DDR)
        +--------------+
               ^
               | (DMA S2MM writes directly to DDR)
        +--------------+
        | DDR3 Memory  |
        +--------------+
               | (Xil_DCacheInvalidateRange forces reload)
               v
        +--------------+
        | L1/L2 Cache  |
        +--------------+
               |
       CPU Core (Reads Rx)
```

### 2.2 Buffer Alignment Requirements
* ARM cache lines are 32 bytes wide.
* When doing cache invalidate operations, if a buffer is not aligned to a cache boundary, invalidating one buffer may unintentionally discard adjacent data belonging to other variables.
* Always enforce **64-byte alignment**:
  ```c
  static u8 TxBuffer[128] __attribute__((aligned(64)));
  static u8 RxBuffer[128] __attribute__((aligned(64)));
  ```

### 2.3 Strict Hardware Trigger Ordering
* **RULE**: Always configure and arm the **Receiver (`S2MM`) BEFORE the Transmitter (`MM2S`)**.
* *Why?* As soon as `MM2S_LENGTH` is written, the DMA controller bursts data across HP0 into the AES core. The core encrypts in 21 clock cycles and immediately asserts `m00_axis_tvalid`. If `S2MM` is not yet armed, backpressure will stall the pipeline or cause FIFO overflows.

---

## 3. Reference NIST Vector
* **Key (128-bit)**: `00000000 00000000 00000000 00000000`
* **Plaintext**: `FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00`
* **Expected Hardware Ciphertext**: `0B 76 FB BE 5D 54 E1 75 B1 3D DD 8E FF 31 A3 C8`

---

## 4. Verification Sequence & Code Implementation

```c
int task_a3_first_correct_transfer(void)
{
    // 1. Prepare data buffers
    memcpy(TxBuffer, pattern, 16);
    memset(RxBuffer, 0, 16);

    // 2. Cache Flush TX, Invalidate RX
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, 16);
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);

    // 3. Arm Receiver first
    Xil_Out32(0x40400000 + 0x48, (u32)RxBuffer);
    Xil_Out32(0x40400000 + 0x58, 16); // Arm RX

    // 4. Trigger Transmitter second
    Xil_Out32(0x40400000 + 0x18, (u32)TxBuffer);
    Xil_Out32(0x40400000 + 0x28, 16); // Trigger TX

    // 5. Poll completion
    while (!(Xil_In32(0x40400000 + 0x04) & (1 << 12))); // MM2S IOC
    while (!(Xil_In32(0x40400000 + 0x34) & (1 << 12))); // S2MM IOC

    // 6. Clear IOC flags
    Xil_Out32(0x40400000 + 0x04, (1 << 12));
    Xil_Out32(0x40400000 + 0x34, (1 << 12));

    // 7. Invalidate RX Cache before reading
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);

    // 8. Verify
    return (memcmp(RxBuffer, gold, 16) == 0) ? 0 : -1;
}
```

