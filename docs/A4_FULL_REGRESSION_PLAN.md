# Task A4: Full Automated Regression Test Suite

## 1. Overview & Objective
Task A4 constructs an autonomous hardware verification harness that cycles through multiple NIST SP 800-38A / FIPS-197 test patterns without human intervention or ILA debugging pauses, printing a concise `X passed, Y failed` status summary.

**Success Criteria**:
- Test harness iterates through all corner-case bit patterns (sequential, all-0, all-1, alternating 0xAA/0x55, multi-block stream).
- Dynamically updates keys and expands round keys on the hardware AES core.
- Concludes with a clean **0-failure** summary report.

---

## 2. Background & Educational Concepts

### 2.1 Hardware Corner-Case Testing
In cryptographic hardware verification, simple arbitrary inputs are insufficient. Hardware synthesis optimizations and S-box lookup pipelines often mask timing faults or bit-toggle issues. Regression suites must stress:
1. **All-Zeros (`0x00...00`)**: Stresses minimum switching activity and verifies S-box constant offset behavior ($S(0x00) = 0x63$).
2. **All-Ones (`0xFF...FF`)**: Stresses maximum simultaneous bit toggles and maximum power-draw switching noise in FPGA lookup tables.
3. **Alternating 0xAA / 0x55 (`10101010...` / `01010101...`)**: Detects adjacent-wire crosstalk, capacitive coupling, and endianness transposition bugs between the 64-bit DMA and 128-bit core width converters.
4. **Multi-Block Stream (Backpressure)**: Verifies that the hardware core can handle continuous streaming without losing block boundaries or dropping the `TLAST` signal.

---

## 3. Test Vectors Definition Table

| Vector ID | Key | Plaintext | Expected Ciphertext | Test Objective |
| :---: | :--- | :--- | :--- | :--- |
| **V1** | `0000...` | `FF EE DD CC ... 11 00` | `0B 76 FB BE ... A3 C8` | Standard Sequential Vector |
| **V2** | `0000...` | `00 00 00 00 ... 00 00` | `66 E9 4B D4 ... 2B 2E` | All-Zero (S-Box Base) |
| **V3** | `0000...` | `FF FF FF FF ... FF FF` | `A1 F6 40 5D ... 3B C4` | All-Ones (Max Switching) |
| **V4** | `0000...` | `AA AA AA AA ... AA AA` | Computed Gold Pattern | 1010 Bit-Toggle Pattern |
| **V5** | `0000...` | `55 55 55 55 ... 55 55` | Computed Gold Pattern | 0101 Bit-Toggle Pattern |
| **V6** | Custom | `32 43 F6 A8 ... 07 34` | FIPS 197 Reference | Dynamic Key Expansion |
| **V7** | `0000...` | 4 × 16 bytes (64-byte burst) | 4 × `0B 76 ... A3 C8` | Continuous Burst Streaming |

---

## 4. Test Harness Implementation

```c
int task_a4_full_regression(void)
{
    int passed = 0, failed = 0;
    int total = sizeof(vectors) / sizeof(vectors[0]);

    for (int i = 0; i < total; i++) {
        aes_set_key(vectors[i].key);
        memcpy(TxBuffer, vectors[i].pt, 16);
        memset(RxBuffer, 0, 16);

        Xil_DCacheFlushRange((UINTPTR)TxBuffer, 16);
        Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);

        dma_s2mm_start((UINTPTR)RxBuffer, 16);
        dma_mm2s_start((UINTPTR)TxBuffer, 16);

        if (dma_wait_completion() != 0) {
            failed++;
            continue;
        }

        Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);

        if (memcmp(RxBuffer, vectors[i].ct, 16) == 0) {
            passed++;
        } else {
            failed++;
        }
    }

    xil_printf("REGRESSION SUMMARY: %d passed, %d failed\n\r", passed, failed);
    return (failed == 0) ? 0 : -1;
}
```

