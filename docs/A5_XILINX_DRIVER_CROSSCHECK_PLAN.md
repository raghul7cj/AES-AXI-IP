# Task A5: Cross-Check vs Official Xilinx Library Driver (`xaxidma.h`)

## 1. Overview & Objective
Task A5 executes the identical set of cryptographic test vectors using Xilinx's standalone Board Support Package (BSP) driver (`xaxidma.h` / `XAxiDma_*` APIs) and compares functionality, software complexity, and cycle overhead against our custom raw register driver.

**Success Criteria**:
- Successfully initialize and run DMA transfers using `XAxiDma_CfgInitialize` and `XAxiDma_SimpleTransfer`.
- Output identical ciphertext across all vectors.
- Quantify performance and footprint trade-offs between raw register access and the vendor driver.

---

## 2. Background & Educational Concepts

### 2.1 Anatomy of the Xilinx Standalone Driver
The official Xilinx driver (`xaxidma.c`) is designed as a universal abstraction layer supporting both Simple DMA and Scatter-Gather (SG) DMA across multiple architectures (MicroBlaze, Zynq-7000, Zynq UltraScale+).

```
+-------------------------------------------------------------+
|                      User Application                       |
+-------------------------------------------------------------+
         |                                           |
         | Raw Register Approach                     | Xilinx Driver Layer
         v                                           v
+------------------+                        +------------------+
| Inlined          |                        | XAxiDma_Lookup-  |
| Xil_Out32 writes |                        | Config / Init    |
+------------------+                        +------------------+
         |                                           |
         | Direct Physical Offset                    | XAxiDma_Simple-
         |                                           | Transfer
         v                                           v
+-------------------------------------------------------------+
|                 AXI DMA Hardware Controller                 |
+-------------------------------------------------------------+
```

### 2.2 Comparison & Architectural Trade-Offs

| Metric | Raw Register Driver (`Xil_Out32`) | Xilinx Standalone Driver (`xaxidma.h`) |
| :--- | :--- | :--- |
| **Code Footprint** | ~50 lines of compact C code | Several KB of compiled object code (`xaxidma.o`, `xaxidma_bdring.o`, `xaxidma_g.o`) |
| **RAM Allocation** | Zero heap or instance memory | Requires `XAxiDma` instance struct in memory |
| **Instruction Overhead** | 2 instructions per transfer trigger | ~40-60 instructions (argument checks, status checks, ring stubs) |
| **Maintainability** | Highly transparent; zero external dependencies | Portable across Vivado versions, but abstracts underlying hardware registers |

---

## 3. Implementation with Xilinx Driver API

```c
#include "xaxidma.h"

XAxiDma AxiDmaInstance;

int task_a5_xilinx_driver_crosscheck(void)
{
    XAxiDma_Config *CfgPtr;
    int Status;

    // 1. Lookup hardware configuration
    CfgPtr = XAxiDma_LookupConfig(XPAR_AXIDMA_0_DEVICE_ID);
    if (!CfgPtr) {
        xil_printf("LookupConfig failed.\n\r");
        return -1;
    }

    // 2. Initialize instance
    Status = XAxiDma_CfgInitialize(&AxiDmaInstance, CfgPtr);
    if (Status != XST_SUCCESS) {
        xil_printf("CfgInitialize failed.\n\r");
        return -1;
    }

    // 3. Disable interrupts (polling mode)
    XAxiDma_IntrDisable(&AxiDmaInstance, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DEVICE_TO_DMA);
    XAxiDma_IntrDisable(&AxiDmaInstance, XAXIDMA_IRQ_ALL_MASK, XAXIDMA_DMA_TO_DEVICE);

    // 4. Cache maintenance
    Xil_DCacheFlushRange((UINTPTR)TxBuffer, 16);
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);

    // 5. Trigger transfers via Xilinx API (RX first, then TX)
    Status = XAxiDma_SimpleTransfer(&AxiDmaInstance, (UINTPTR)RxBuffer, 16, XAXIDMA_DEVICE_TO_DMA);
    Status |= XAxiDma_SimpleTransfer(&AxiDmaInstance, (UINTPTR)TxBuffer, 16, XAXIDMA_DMA_TO_DEVICE);

    // 6. Poll completion
    while (XAxiDma_Busy(&AxiDmaInstance, XAXIDMA_DEVICE_TO_DMA));
    while (XAxiDma_Busy(&AxiDmaInstance, XAXIDMA_DMA_TO_DEVICE));

    // 7. Refresh Cache & Verify
    Xil_DCacheInvalidateRange((UINTPTR)RxBuffer, 16);
    int match = (memcmp(RxBuffer, gold, 16) == 0);

    xil_printf("[TASK A5] Xilinx Driver Match: [%s]\n\r", match ? "PASS" : "FAIL");
    return match ? 0 : -1;
}
```

