# Linux Kernel Module: AES-DMA Char Device (Polling Mode — v1)
## Target: PYNQ-Z2 (XC7Z020) — PYNQ Linux / PetaLinux

---

## Hardware Constraints That Shape This Entire Plan

Before anything else — the hardware facts that lock in the design:

| Constraint | Detail | Impact on Driver |
|---|---|---|
| DMA mode | Direct Register (no Scatter-Gather) | Simple single-transfer model |
| IRQ wiring | **No interrupt line from DMA to PS GIC** | Cannot use `request_irq`, must poll |
| AES IP | No interrupt capability | Transfer done = DMA S2MM goes idle |
| Max transfer | `C_SG_LENGTH_WIDTH=14` → 16,383 bytes | Buffer size cap enforced in ioctl |
| AXI Data width | DMA=64-bit, AES=128-bit (width converters present) | Minimum 16-byte aligned transfers |
| Cache | HP0 is non-coherent | Must handle cache manually |

---

## Is Polling Suboptimal in Linux?

**Yes, and here's the precise reason:**

In bare-metal, you own the entire CPU. Busy-polling burns cycles but there is nothing else running, so zero penalty.

In Linux, the CPU runs dozens of processes and kernel threads. If your driver busy-polls in kernel code without yielding, it **holds the CPU hostage** for the duration of the DMA transfer. The scheduler cannot preempt kernel code that does not voluntarily yield (on non-preemptible kernels). Other processes stall. `dmesg` can show "soft lockup" warnings if you spin for more than ~10 seconds.

**For v1 with this hardware — it is completely acceptable.** A 16-byte AES transfer at 75 MHz takes ~4-5 µs. Even a 8 KB burst takes ~40 µs. At these durations, the kernel won't complain and no user will notice. Just add `cond_resched()` inside the poll loop to be a good citizen.

```
v1 approach: polling with cond_resched()     <- you are building this
v2 future:   add IRQ wiring in Vivado + request_irq in driver
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    User Space Process                     │
│                                                          │
│   int fd = open("/dev/aes_dma", O_RDWR);                 │
│   ioctl(fd, AES_IOC_SET_KEY, &key);                      │
│   ioctl(fd, AES_IOC_ENCRYPT, &enc);   ← blocks here     │
│                                           until done     │
└──────────────────┬───────────────────────────────────────┘
                   │  syscall (ioctl)
                   ▼
┌──────────────────────────────────────────────────────────┐
│                  Kernel Space                             │
│                                                          │
│  aes_dma_ioctl()                                         │
│    ├─ copy_from_user(tx_virt, user_plaintext, len)       │
│    ├─ aes_dma_do_transfer(dev, len)                      │
│    │    ├─ arm S2MM: iowrite32(rx_phys, S2MM_DA)         │
│    │    │            iowrite32(len, S2MM_LENGTH)          │
│    │    ├─ fire MM2S: iowrite32(tx_phys, MM2S_SA)        │
│    │    │             iowrite32(len, MM2S_LENGTH)         │
│    │    └─ poll loop: while(!IDLE) { cond_resched(); }   │
│    └─ copy_to_user(user_ciphertext, rx_virt, len)        │
│                                                          │
│  File:  aes_dma_driver.c                                 │
│  Regs:  aes_dma_regs.h  (identical offsets to bare-metal)│
│  IOCTL: aes_dma_ioctl.h (shared with user-space app)    │
└──────────────────┬───────────────────────────────────────┘
                   │  ioremap'd MMIO + dma_alloc_coherent
                   ▼
┌──────────────────────────────────────────────────────────┐
│                Physical Hardware                          │
│  AXI DMA @ 0x40400000   AES-128 IP @ 0x40000000         │
│  (via HP0 AXI port — non-coherent)                       │
└──────────────────────────────────────────────────────────┘
```

---

## File Structure

```
linux_kernel_driver/
├── Makefile                  ← kbuild cross-compile Makefile
├── aes_dma_driver.c          ← ALL driver code lives here (single file for v1)
├── aes_dma_regs.h            ← Register offsets + access macros (port from bare-metal)
├── aes_dma_ioctl.h           ← Shared: kernel + user-space both include this
└── test/
    ├── aes_dma_test.c        ← User-space NIST vector test + latency benchmark
    └── Makefile
```

---

## Layer-by-Layer Teaching + Implementation

---

### LAYER 0 — The Mental Model: What a Kernel Module Actually Is

A kernel module (`.ko` file) is a piece of code that the kernel loads into its own address space at runtime. It runs at the same privilege level as the kernel itself. There is no sandbox. A null pointer dereference crashes the entire system.

```c
/* This is the entire skeleton of a kernel module */
#include <linux/module.h>
#include <linux/init.h>

static int __init aes_dma_init(void)
{
    pr_info("aes_dma: module loaded\n");   /* goes to dmesg */
    return 0;    /* non-zero = module load fails */
}

static void __exit aes_dma_exit(void)
{
    pr_info("aes_dma: module removed\n");
}

module_init(aes_dma_init);
module_exit(aes_dma_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("AES-DMA polling driver for PYNQ-Z2");
```

**Build lifecycle:**
```
your_driver.c  →  make (kbuild)  →  aes_dma.ko
aes_dma.ko     →  insmod         →  aes_dma_init() runs
               →  rmmod          →  aes_dma_exit() runs
```

**Debugging output:**
```bash
dmesg | tail -10        # see your pr_info / pr_err messages
dmesg -w                # live tail (like tail -f)
```

---

### LAYER 1 — Platform Driver: How Your Driver Finds the Hardware

The platform driver pattern answers: "how does the kernel know my driver exists, and where the hardware is?"

**Step 1: Write a Device Tree node** (describes hardware to kernel)
```dts
/* In aes_dma_overlay.dts */
/dts-v1/;
/plugin/;

/ {
    fragment@0 {
        target-path = "/";
        __overlay__ {
            aes_dma@40400000 {
                compatible = "xlnx,aes-dma-1.0";    /* KEY: must match driver */
                reg = <0x40400000 0x10000            /* DMA registers */
                       0x40000000 0x1000>;           /* AES IP registers */
                /* No interrupts entry - hardware has no IRQ wiring */
            };
        };
    };
};
```

**Step 2: Driver declares what it handles**
```c
static const struct of_device_id aes_dma_of_match[] = {
    { .compatible = "xlnx,aes-dma-1.0" },  /* must match DT compatible string */
    { }
};
MODULE_DEVICE_TABLE(of, aes_dma_of_match);
```

**Step 3: Kernel matches DT node → calls probe()**
```c
/* probe() is called by the kernel when it finds a matching DT node */
static int aes_dma_probe(struct platform_device *pdev)
{
    pr_info("aes_dma: probe() called — hardware found in DT\n");
    /* pdev contains the DT info (base addresses, etc.) */
    return 0;
}

static int aes_dma_remove(struct platform_device *pdev)
{
    pr_info("aes_dma: remove() called\n");
    return 0;
}

static struct platform_driver aes_dma_driver = {
    .probe  = aes_dma_probe,
    .remove = aes_dma_remove,
    .driver = {
        .name           = "aes_dma",
        .of_match_table = aes_dma_of_match,
    },
};

/* This macro auto-generates module_init/module_exit that register the driver */
module_platform_driver(aes_dma_driver);
```

**Key insight:** `probe()` is not called by your `init()`. It is called by the kernel's device model when it boots (or when you load a DT overlay). This is the "device tree match" event.

---

### LAYER 2 — ioremap: Making Hardware Registers Accessible

Your bare-metal driver wrote:
```c
Xil_Out32(0x40400000 + MM2S_DMACR, DMACR_RS);
```

That works because in bare-metal, virtual address = physical address (MMU off or identity-mapped).

In Linux, the MMU is enabled. Physical address `0x40400000` is not in the kernel's virtual address space. You need to ask the kernel to create a mapping:

```c
void __iomem *dma_base;

/* Inside probe(): */
struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0); /* first reg entry */
if (!res) {
    dev_err(&pdev->dev, "failed to get DMA resource\n");
    return -ENODEV;
}

/* devm_ prefix = "device managed" = automatically cleaned up when driver removes */
dma_base = devm_ioremap_resource(&pdev->dev, res);
if (IS_ERR(dma_base))
    return PTR_ERR(dma_base);

/* Now use it: */
iowrite32(DMACR_RS, dma_base + MM2S_DMACR);   /* write */
u32 val = ioread32(dma_base + MM2S_DMASR);     /* read  */
```

**The `__iomem` annotation:**
- `void __iomem *` tells the compiler (and the sparse static analyzer) "this pointer points to MMIO, not RAM"
- Never dereference with `*ptr` — always use `ioread32` / `iowrite32`
- Prevents optimizer from reordering/caching MMIO accesses

**`devm_` resources (device-managed):**
- Any resource allocated with `devm_` is automatically freed when the device is removed
- No need to manually call `iounmap()` in `remove()` — kernel does it
- Use `devm_` variants for everything in probe() — it prevents resource leaks

---

### LAYER 3 — DMA Buffers: dma_alloc_coherent

Your bare-metal driver had:
```c
static u8 TxBuf[4096] __attribute__((aligned(64)));
static u8 RxBuf[4096] __attribute__((aligned(64)));
```

These lived at fixed physical addresses. You passed `(u32)TxBuf` directly to the DMA register.

In Linux you cannot do that because:
1. The virtual address of a kernel buffer ≠ its physical address
2. You need to tell the DMA engine the **physical** address (what the AXI bus sees)
3. The CPU needs a **virtual** address to read/write the buffer

`dma_alloc_coherent` gives you both:

```c
#define BUF_SIZE    (16 * 1024)   /* 16 KB, larger than max transfer */

dma_addr_t  tx_phys, rx_phys;    /* physical addresses → DMA registers */
void       *tx_virt, *rx_virt;   /* virtual addresses  → CPU memcpy  */

/* Inside probe(): */
tx_virt = dma_alloc_coherent(&pdev->dev, BUF_SIZE, &tx_phys, GFP_KERNEL);
if (!tx_virt)
    return -ENOMEM;

rx_virt = dma_alloc_coherent(&pdev->dev, BUF_SIZE, &rx_phys, GFP_KERNEL);
if (!rx_virt) {
    dma_free_coherent(&pdev->dev, BUF_SIZE, tx_virt, tx_phys);
    return -ENOMEM;
}

/* Usage: */
memcpy(tx_virt, plaintext, len);                     /* CPU writes via virtual */
iowrite32((u32)tx_phys, dma_base + MM2S_SA);         /* DMA reads via physical */
```

**Why "coherent":** On Zynq's HP0 port, there is no hardware cache coherency between PS cache and PL DMA. `dma_alloc_coherent` allocates memory as **non-cacheable** in the MMU page tables. This means CPU writes go directly to DDR (bypassing cache) and DMA reads see fresh data immediately. No manual flush/invalidate needed — the coherent allocator handles it by not caching at all.

**Cleanup in `remove()`:**
```c
dma_free_coherent(dev, BUF_SIZE, tx_virt, tx_phys);
dma_free_coherent(dev, BUF_SIZE, rx_virt, rx_phys);
```
(There is no `devm_dma_alloc_coherent` in older kernels, so you free manually in `remove()`.)

---

### LAYER 4 — Polling in Linux: The Right Way

**The wrong way (bare-metal style):**
```c
/* BAD in kernel — starves other processes */
while (!(ioread32(dma_base + S2MM_DMASR) & DMASR_IDLE))
    ;   /* pure spin */
```

**The right way for v1 (polling with yield):**
```c
static int aes_dma_poll_complete(struct aes_dma_dev *dev)
{
    unsigned long timeout = jiffies + msecs_to_jiffies(5000);  /* 5 second timeout */

    /* Poll S2MM IDLE bit */
    while (!(ioread32(dev->dma_base + S2MM_DMASR) & DMASR_IDLE)) {

        /* Check timeout */
        if (time_after(jiffies, timeout)) {
            dev_err(dev->dev, "S2MM poll timeout — DMA stalled\n");
            return -ETIMEDOUT;
        }

        /* Check for DMA error flags */
        if (ioread32(dev->dma_base + S2MM_DMASR) & DMASR_ERR_MASK) {
            dev_err(dev->dev, "S2MM DMA error: 0x%08x\n",
                    ioread32(dev->dma_base + S2MM_DMASR));
            return -EIO;
        }

        /* Voluntarily yield CPU to scheduler between polls.
         * This is what makes polling acceptable in kernel:
         * other processes can run between your checks.
         * For ~5 us transfers this loop barely runs twice anyway. */
        cond_resched();
    }

    /* Clear IOC flag (W1C) — same pattern as bare-metal */
    iowrite32(DMASR_IOC_IRQ, dev->dma_base + S2MM_DMASR);
    return 0;
}
```

**What `cond_resched()` does:**
```
Normal kernel code:  no preemption until you return to user space
                     → other processes wait

cond_resched():      checks scheduler — if a higher-priority task is waiting,
                     voluntarily yields the CPU to it
                     → good citizen behavior
                     → no "soft lockup" warnings in dmesg
```

**Why it's fine for v1:**  
A 16-byte AES transfer takes ~5 µs. A 8 KB burst takes ~40 µs. `cond_resched()` in a tight loop that exits in 5–40 µs is negligible overhead. The scheduler won't even notice.

**Suboptimality acknowledged:**  
The ioctl call *blocks* user-space for the duration of the DMA poll. A second process calling `ioctl(ENCRYPT)` simultaneously would block on the mutex (see Layer 5). This is fine for a single-client driver. The v2 upgrade path is: wire IRQ in Vivado → `request_irq()` → `wait_event_interruptible()` → non-blocking.

---

### LAYER 5 — Mutex: Protecting Hardware from Concurrent Access

Multiple processes can have `/dev/aes_dma` open simultaneously. Both could call `ioctl(ENCRYPT)` at the same time. Without serialization, both would write to the same DMA registers simultaneously — corrupted transfer.

```c
/* In device state struct */
struct aes_dma_dev {
    struct mutex    lock;    /* one transfer at a time */
    ...
};

/* In probe(): */
mutex_init(&dev->lock);

/* In ioctl() handler: */
static long aes_dma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aes_dma_dev *dev = filp->private_data;

    /* Acquire mutex — blocks if another process is mid-transfer.
     * _interruptible: if user sends Ctrl-C while waiting, returns -ERESTARTSYS
     * (without this, Ctrl-C would be ignored while blocked on mutex) */
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    /* ... do transfer ... */

    mutex_unlock(&dev->lock);
    return 0;
}
```

**Rule:** Every access to shared hardware state (`dma_base`, `tx_virt`, etc.) must happen while holding the mutex.

---

### LAYER 6 — Character Device: Creating /dev/aes_dma

A character device is how user-space programs talk to your driver via standard file operations (`open`, `read`, `write`, `ioctl`). The kernel assigns a major:minor number pair to identify it.

```c
/* Step 1: Define the file_operations table */
static const struct file_operations aes_dma_fops = {
    .owner          = THIS_MODULE,
    .open           = aes_dma_open,
    .release        = aes_dma_release,
    .unlocked_ioctl = aes_dma_ioctl,
    /* No read/write — all interaction via ioctl for this driver */
};

/* Step 2: Register in probe() */
/* Allocate a dynamic major:minor number */
ret = alloc_chrdev_region(&dev->devno, 0, 1, "aes_dma");
if (ret < 0) return ret;

/* Attach file_operations to the cdev */
cdev_init(&dev->cdev, &aes_dma_fops);
dev->cdev.owner = THIS_MODULE;
ret = cdev_add(&dev->cdev, dev->devno, 1);
if (ret < 0) { unregister_chrdev_region(dev->devno, 1); return ret; }

/* Create /dev/aes_dma node (needs a class first) */
dev->cls = class_create(THIS_MODULE, "aes_dma");
dev->device = device_create(dev->cls, NULL, dev->devno, NULL, "aes_dma");

/* Step 3: open() stores dev* so ioctl can find it */
static int aes_dma_open(struct inode *inode, struct file *filp)
{
    /* container_of: finds the aes_dma_dev that contains this cdev */
    struct aes_dma_dev *dev = container_of(inode->i_cdev, struct aes_dma_dev, cdev);
    filp->private_data = dev;   /* save pointer for ioctl/release */
    return 0;
}

static int aes_dma_release(struct inode *inode, struct file *filp)
{
    return 0;   /* nothing to clean up per-fd */
}

/* Step 4: Cleanup in remove() */
device_destroy(dev->cls, dev->devno);
class_destroy(dev->cls);
cdev_del(&dev->cdev);
unregister_chrdev_region(dev->devno, 1);
```

**What the user sees after this:**
```bash
ls -la /dev/aes_dma        # crw------- 1 root root 245, 0 ...
chmod 666 /dev/aes_dma     # allow non-root access (or use udev rule)
```

---

### LAYER 7 — ioctl: The Control Interface

ioctl is the standard mechanism for device-specific commands that don't fit `read`/`write`. All AES operations go through ioctl.

**Shared header (both kernel and user-space include this):**
```c
/* aes_dma_ioctl.h */
#ifndef AES_DMA_IOCTL_H
#define AES_DMA_IOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint32_t __u32;
#endif

#define AES_DMA_MAGIC   'A'
#define MAX_AES_BYTES   16383   /* C_SG_LENGTH_WIDTH=14 → 2^14 - 1 */

struct aes_key_arg {
    __u8 key[16];             /* 128-bit AES key */
};

struct aes_encrypt_arg {
    __u64 plaintext_ptr;      /* user-space virtual address of input  */
    __u64 ciphertext_ptr;     /* user-space virtual address of output */
    __u32 length;             /* bytes: must be multiple of 16, max 16383 */
};

#define AES_IOC_SET_KEY    _IOW(AES_DMA_MAGIC, 1, struct aes_key_arg)
#define AES_IOC_ENCRYPT    _IOWR(AES_DMA_MAGIC, 2, struct aes_encrypt_arg)
#define AES_IOC_RESET      _IO(AES_DMA_MAGIC,  3)
#define AES_IOC_STATUS     _IOR(AES_DMA_MAGIC,  4, __u32)

#endif
```

> **Why `__u64` for pointers?** On a 32-bit ARM kernel with 64-bit userspace (PYNQ), or vice versa, pointer sizes differ. Using `__u64` for pointer-as-integer ensures the struct has the same layout on both sides. Cast with `(void __user *)(uintptr_t)arg.plaintext_ptr` in kernel.

**ioctl handler (kernel side):**
```c
static long aes_dma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aes_dma_dev *dev = filp->private_data;
    int ret;

    /* Validate command belongs to this driver */
    if (_IOC_TYPE(cmd) != AES_DMA_MAGIC)
        return -ENOTTY;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    switch (cmd) {

    case AES_IOC_SET_KEY: {
        struct aes_key_arg karg;
        if (copy_from_user(&karg, (void __user *)arg, sizeof(karg))) {
            ret = -EFAULT; break;
        }
        ret = aes_program_key(dev, karg.key);
        break;
    }

    case AES_IOC_ENCRYPT: {
        struct aes_encrypt_arg earg;
        if (copy_from_user(&earg, (void __user *)arg, sizeof(earg))) {
            ret = -EFAULT; break;
        }
        /* Validate */
        if (earg.length == 0 || earg.length > MAX_AES_BYTES || earg.length % 16 != 0) {
            ret = -EINVAL; break;
        }
        /* Copy plaintext user → kernel TX buffer */
        if (copy_from_user(dev->tx_virt,
                           (void __user *)(uintptr_t)earg.plaintext_ptr,
                           earg.length)) {
            ret = -EFAULT; break;
        }
        /* Execute DMA transfer (polling) */
        ret = aes_dma_do_transfer(dev, earg.length);
        if (ret) break;
        /* Copy ciphertext kernel RX buffer → user */
        if (copy_to_user((void __user *)(uintptr_t)earg.ciphertext_ptr,
                         dev->rx_virt, earg.length)) {
            ret = -EFAULT; break;
        }
        break;
    }

    case AES_IOC_RESET:
        ret = aes_dma_hw_init(dev);
        break;

    case AES_IOC_STATUS: {
        __u32 status = ioread32(dev->dma_base + S2MM_DMASR);
        ret = copy_to_user((void __user *)arg, &status, sizeof(status)) ? -EFAULT : 0;
        break;
    }

    default:
        ret = -ENOTTY;
    }

    mutex_unlock(&dev->lock);
    return ret;
}
```

---

### LAYER 8 — The DMA Transfer Function (Full Polling)

This directly mirrors bare-metal but uses kernel MMIO accessors:

```c
static int aes_dma_hw_init(struct aes_dma_dev *dev)
{
    /* Soft reset both channels (same as bare-metal dma_init) */
    iowrite32(DMACR_RESET, dev->dma_base + MM2S_DMACR);
    iowrite32(DMACR_RESET, dev->dma_base + S2MM_DMACR);

    while (ioread32(dev->dma_base + MM2S_DMACR) & DMACR_RESET) cond_resched();
    while (ioread32(dev->dma_base + S2MM_DMACR) & DMACR_RESET) cond_resched();

    /* Clear any pending flags (W1C) */
    iowrite32(DMASR_IOC_IRQ | DMASR_ERR_MASK, dev->dma_base + MM2S_DMASR);
    iowrite32(DMASR_IOC_IRQ | DMASR_ERR_MASK, dev->dma_base + S2MM_DMASR);

    /* Set RS=1 on both channels */
    iowrite32(DMACR_RS, dev->dma_base + MM2S_DMACR);
    iowrite32(DMACR_RS, dev->dma_base + S2MM_DMACR);

    /* Wait for Halted to clear */
    while (ioread32(dev->dma_base + MM2S_DMASR) & DMASR_HALTED) cond_resched();
    while (ioread32(dev->dma_base + S2MM_DMASR) & DMASR_HALTED) cond_resched();

    dev_info(dev->dev, "DMA initialized: both channels running\n");
    return 0;
}

static int aes_dma_do_transfer(struct aes_dma_dev *dev, u32 len)
{
    unsigned long timeout;

    /* Step 1: Arm S2MM (sink) first */
    iowrite32((u32)dev->rx_phys, dev->dma_base + S2MM_DA);
    iowrite32(len,               dev->dma_base + S2MM_LENGTH);  /* arms S2MM */

    /* Step 2: Fire MM2S (source) */
    iowrite32((u32)dev->tx_phys, dev->dma_base + MM2S_SA);
    iowrite32(len,               dev->dma_base + MM2S_LENGTH);  /* triggers MM2S */

    /* Step 3: Poll S2MM IDLE (transfer done when S2MM goes idle) */
    timeout = jiffies + msecs_to_jiffies(5000);

    while (!(ioread32(dev->dma_base + S2MM_DMASR) & DMASR_IDLE)) {
        if (time_after(jiffies, timeout)) {
            dev_err(dev->dev, "S2MM timeout: DMASR=0x%08x\n",
                    ioread32(dev->dma_base + S2MM_DMASR));
            aes_dma_hw_init(dev);   /* reset to known state */
            return -ETIMEDOUT;
        }
        if (ioread32(dev->dma_base + S2MM_DMASR) & DMASR_ERR_MASK) {
            dev_err(dev->dev, "S2MM error: DMASR=0x%08x\n",
                    ioread32(dev->dma_base + S2MM_DMASR));
            aes_dma_hw_init(dev);
            return -EIO;
        }
        cond_resched();   /* yield between polls */
    }

    /* Clear IOC (W1C) */
    iowrite32(DMASR_IOC_IRQ, dev->dma_base + S2MM_DMASR);
    iowrite32(DMASR_IOC_IRQ, dev->dma_base + MM2S_DMASR);

    return 0;
}
```

---

### LAYER 9 — AES Key Programming

The AES IP has key registers at specific offsets from `0x40000000`. The key programming sequence from bare-metal carries over unchanged — only `Xil_Out32` becomes `iowrite32`:

```c
/* AES IP register offsets (from your XSA) */
#define AES_KEY_0   0x10   /* Key word 0 (MSB) */
#define AES_KEY_1   0x14
#define AES_KEY_2   0x18
#define AES_KEY_3   0x1C   /* Key word 3 (LSB) */

static int aes_program_key(struct aes_dma_dev *dev, const u8 *key)
{
    u32 w0 = (key[0]  << 24) | (key[1]  << 16) | (key[2]  << 8) | key[3];
    u32 w1 = (key[4]  << 24) | (key[5]  << 16) | (key[6]  << 8) | key[7];
    u32 w2 = (key[8]  << 24) | (key[9]  << 16) | (key[10] << 8) | key[11];
    u32 w3 = (key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15];

    iowrite32(w0, dev->aes_base + AES_KEY_0);
    iowrite32(w1, dev->aes_base + AES_KEY_1);
    iowrite32(w2, dev->aes_base + AES_KEY_2);
    iowrite32(w3, dev->aes_base + AES_KEY_3);

    dev->key_valid = true;
    dev_dbg(dev->dev, "AES key programmed\n");
    return 0;
}
```

> **Note:** Verify the AES key register offsets from your XSA `.hwh` file before writing. Search for `s_axi_lite` interface on the `axi_aes_ip_0` module to find the register map.

---

## Complete Device State Struct

```c
struct aes_dma_dev {
    /* Hardware register access */
    void __iomem    *dma_base;      /* ioremap'd 0x40400000 */
    void __iomem    *aes_base;      /* ioremap'd 0x40000000 */

    /* DMA buffers */
    void            *tx_virt;       /* virtual ptr (CPU memcpy) */
    dma_addr_t       tx_phys;       /* physical addr (MM2S_SA) */
    void            *rx_virt;
    dma_addr_t       rx_phys;       /* physical addr (S2MM_DA) */
    size_t           buf_size;

    /* Char device */
    struct cdev      cdev;
    dev_t            devno;
    struct class    *cls;
    struct device   *device;

    /* Synchronization */
    struct mutex     lock;

    /* AES state */
    bool             key_valid;

    /* Parent device (needed for dma_alloc_coherent) */
    struct device   *dev;
};
```

---

## Milestone Plan (B1 → B4)

### B1 — Module Skeleton (Est. 1 hour)

**Goal:** `insmod` works, DT match triggers `probe()`, `rmmod` works.

**What you learn:** Module lifecycle, kbuild, `pr_info`/`dmesg`, platform driver pattern.

**Done when:**
```bash
sudo insmod aes_dma.ko
dmesg | grep aes_dma
# [  42.1] aes_dma: probe() called — DMA base from DT: 0x40400000
sudo rmmod aes_dma
dmesg | grep aes_dma
# [  50.2] aes_dma: remove() called
```

**Files needed:** `aes_dma_driver.c` (skeleton only), `Makefile`, `aes_dma_overlay.dts`

---

### B2 — Register Access + Hardware Init (Est. 2 hours)

**Goal:** `ioremap` both register regions, call `aes_dma_hw_init()`, dump DMA status via debugfs. Verify values match bare-metal `dma_dump_status()` output.

**What you learn:** `ioremap`, `ioread32`/`iowrite32`, `devm_` resources, debugfs.

**Done when:**
```bash
cat /sys/kernel/debug/aes_dma/status
# MM2S_DMASR: 0x00000002  (Halted=0 Idle=1)
# S2MM_DMASR: 0x00000002  (Halted=0 Idle=1)
```

**Files needed:** Add `aes_dma_regs.h`, implement `probe()` fully, add debugfs dump.

---

### B3 — DMA Buffers + Character Device (Est. 2 hours)

**Goal:** `/dev/aes_dma` exists. `open()` and `close()` work. `dma_alloc_coherent` allocates TX/RX buffers.

**What you learn:** `dma_alloc_coherent`, char device registration, `cdev`, `file_operations`.

**Done when:**
```bash
ls -la /dev/aes_dma
# crw------- 1 root root 245, 0 ...
python3 -c "fd = open('/dev/aes_dma', 'rb'); print('opened ok'); fd.close()"
```

---

### B4 — First Correct Encryption via ioctl (Est. 3 hours)

**Goal:** User-space calls `ioctl(SET_KEY)` + `ioctl(ENCRYPT)` and gets correct ciphertext matching NIST AES-128 vector.

**What you learn:** ioctl design, `copy_from_user`/`copy_to_user`, full polling transfer loop, mutex.

**Done when:**
```bash
./aes_dma_test
# Plaintext : 6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a
# Ciphertext: 3a d7 7b b4 0d 7a 36 60 a8 9e ca f3 24 66 ef 97
# Expected  : 3a d7 7b b4 0d 7a 36 60 a8 9e ca f3 24 66 ef 97
# [PASS] NIST vector verified
```

---

### B5 — Latency Benchmark + Results Doc (Est. 1 hour)

**Goal:** Measure user-space ioctl latency with `clock_gettime`. Document Linux overhead vs bare-metal 4.675 µs.

**Done when:** `docs/LINUX_DRIVER_RESULTS.md` written with 100-run statistics.

---

## Open Questions to Resolve in B1

> [!IMPORTANT]
> Before writing B2 code, verify the AES IP register offsets:
> - Open `xsa_unzipped/aes_dma_loop.hwh`
> - Find `axi_aes_ip_0` module
> - Look for `s_axi_lite` port → the register map for key input
> - The key register offsets used in bare-metal task_a4 are the reference

> [!IMPORTANT]
> Verify the DT compatible string approach:
> - On PYNQ Linux, check if configfs DT overlays are supported: `ls /sys/kernel/config/device-tree/`
> - If not, the DT node must be baked into the kernel DTB (requires PetaLinux rebuild)
> - Alternative: PYNQ's `xlnk` / `pynq` Python library may provide a simpler hardware access path for PYNQ-specific boards

---

## What NOT to do in v1

- ❌ Do not use `udelay()` or `mdelay()` in the poll loop — they busy-wait and don't yield
- ❌ Do not allocate buffers with `kmalloc` + manual cache flush — use `dma_alloc_coherent`
- ❌ Do not store the physical address in `dev->tx_virt` or vice versa — keep them separate
- ❌ Do not call `copy_from_user` while holding a spinlock (you're not using spinlocks in v1, just noting the rule)
- ❌ Do not `#include <stdio.h>` or any userspace header in kernel code — use `<linux/...>` headers only
- ✅ Do use `dev_err()` / `dev_info()` instead of `printk()` — includes device name in output automatically

---

## Verification Plan

| Milestone | Test | Pass Criteria |
|---|---|---|
| B1 | `insmod`/`rmmod` + `dmesg` | probe/remove messages appear |
| B2 | Read debugfs regs | `DMASR = 0x00000002` on both channels |
| B3 | `open("/dev/aes_dma")` from Python | No error, `dmesg` shows open |
| B4 | `./aes_dma_test` | NIST vector match `[PASS]` |
| B4 | `./aes_dma_test` with 256-byte input | Multi-block correct |
| B5 | Latency benchmark | Mean latency printed, < 1 ms |

---

*Plan complete. Start with B1. Hardware knowledge from A2–A6 is your biggest advantage — the registers are identical.*
