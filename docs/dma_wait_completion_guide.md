# Deep Dive: `dma_wait_completion()` & Completion Synchronization

**Target Core**: Xilinx AXI DMA (Direct Register / Simple Mode)  
**Channel Status Registers**: `MM2S_DMASR` (`0x40400004`), `S2MM_DMASR` (`0x40400034`)  
**Associated Flags**: `DMASR_IDLE` (Bit 1), `DMASR_IOC_IRQ` (Bit 12), `DMASR_ERR_MASK` (Bits 4, 5, 6)

---

## 1. What Happens During a Transfer in Hardware?

When a transfer is initiated (by writing to `S2MM_LENGTH` and `MM2S_LENGTH`), the DMA hardware transitions through distinct states:

```
State:        [IDLE / READY]  --->  [TRANSFER ACTIVE]  --->  [TRANSFER COMPLETE]
Idle bit:          1                      0                         1
IOC_Irq bit:       0                      0                         1
Error bits:        0                      0                         0 (or 1 if fault)
```

1. **Before Trigger**: 
   - `DMASR_IDLE = 1` (no active burst)
   - `DMASR_IOC_IRQ = 0`
2. **Transfer In-Flight**:
   - The moment `LENGTH` is written, `DMASR_IDLE` drops to `0`.
   - The DMA bus master requests HP0 memory transactions.
   - `dma_mm2s_busy()` returns `1`.
3. **Transfer Finished**:
   - The last data beat is transferred (and for S2MM, when `TLAST` is seen or byte count is exhausted).
   - The DMA hardware asserts `DMASR_IOC_IRQ = 1`.
   - The DMA hardware asserts `DMASR_IDLE = 1`.
   - `dma_mm2s_busy()` returns `0`.

---

## 2. Corner Cases: Why Hardware Can Hang Without Setting IOC

### Corner Case 1: Pipeline Stall / Deadlock
- If downstream logic drops `TREADY` or the AES IP pipeline stalls, the DMA cannot push data.
- **Consequence**: The transfer never completes, `IOC` is never asserted, and an unmonitored `while(busy)` loop will freeze the CPU forever.

### Corner Case 2: S2MM Byte Count / TLAST Mismatch
- The S2MM (receiver) channel finishes only when:
  1. Exactly `S2MM_LENGTH` bytes are received, **OR**
  2. The stream asserts `TLAST`.
- If fewer bytes arrive and `TLAST` is missing, the receiver stays busy indefinitely waiting for remaining beats.

### Corner Case 3: Bus Error Abort
- If an address decode or slave fault occurs (`DMASlvErr`, `DMADecErr`), the core enters an error halt state.
- **`IOC` is never asserted** because the transfer aborted.

---

## 3. Production Implementation: Timeout + Error Check + Verified W1C

To prevent CPU hangs and handle all corner cases, the driver combines three layers of defense:

1. **Software Timeout Loop**: Decrements a loop counter (`timeout = 10000000`). If hardware locks up, the loop aborts and prints a descriptive error message instead of bricking execution.
2. **Immediate Bus Error Detection**: Inspects `DMASR_ERR_MASK` on every iteration.
3. **Verified W1C Clear**: Only writes to clear `DMASR_IOC_IRQ` if the flag is actively confirmed high (`if (dma_read(...) & DMASR_IOC_IRQ)`).

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

---

## 4. Why Check Before Writing W1C?

In hardware registers:
- Writing `0` does nothing.
- Writing `1` clears the bit back to `0`.

While writing `DMASR_IOC_IRQ` directly is safe, wrapping it in:
```c
if (dma_read(MM2S_DMASR) & DMASR_IOC_IRQ) {
    dma_write(MM2S_DMASR, DMASR_IOC_IRQ);
}
```
provides **defensive programming**:
1. It avoids unnecessary write transactions across the `AXI-Lite` bus if the bit was not set (e.g., if an error or timeout triggered loop exit).
2. It confirms the hardware reached completion before sending the clear command.
