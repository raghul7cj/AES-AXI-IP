# AES-128 Test Suite – Vitis & ILA Integration Guide

This guide explains how to set up the **Vitis** software project, program the **Pynq‑Z2** FPGA, and use the **Integrated Logic Analyzer (ILA)** for debugging the AES‑128 encryption core. The test application is designed to validate the core with various patterns and includes a special pause before the 0xFF test to allow ILA triggering.

## Prerequisites

- **Hardware:** Pynq‑Z2 board, USB‑UART cable (included), micro‑USB for programming/power.
- **Software:**
  - Vivado Design Suite 2022.2 (including Vitis)
  - Serial terminal (TeraTerm, Putty, etc.) – **115200 baud, 8N1, no flow control**
- **FPGA Design:** A Vivado project containing:
  - Custom AES‑128 IP (encryption only)
  - AXI DMA
  - UART (for console)
  - ILA core (optional, but required for debug)

## Hardware Setup

1. Connect the Pynq‑Z2 to your PC via the **USB‑UART** port (the one labeled "UART" or "PROG"). This provides both programming and serial communication.
2. Set the board’s boot jumpers to **JTAG mode** (typically both jumpers on the **SD** position for programming via JTAG; refer to Pynq‑Z2 documentation).
3. Power on the board.

## Building the Vitis Application

1. Launch **Vitis**.
2. Create a new application project:
   - Platform: select the hardware platform (`.xsa` file exported from Vivado).
   - Name: e.g., `aes128_test`.
   - Select the `Hello World` template (you will replace the source).
3. Copy the provided C source file (containing `main`, `run_vector`, `wait_for_ila_setup`, etc.) into the `src` folder of the project.
4. Build the project (Ctrl+B). Ensure no compilation errors.

## Programming the FPGA

You can program the bitstream either from **Vivado** or directly from **Vitis**.

### Option A: Using Vivado Hardware Manager
1. Open Vivado.
2. Open the hardware manager and connect to the Pynq‑Z2 (auto‑detect).
3. Program the device with the bitstream that includes the ILA core.
4. Keep Vivado open – you will use it to arm the ILA later.

### Option B: Using Vitis (if the bitstream is included in the platform)
1. In Vitis, right‑click the application project and select **Launch Hardware**.
2. The FPGA will be programmed automatically when the application runs (if the platform includes the bitstream). However, for ILA debug, it is often easier to use Vivado.

## Running the Test Suite (Normal Mode)

If you do **not** need ILA capture, simply run the application without any breakpoints:

1. In Vitis, click **Run** (or **Debug** if you want to see console output in the Debug perspective).
2. The program will execute all test vectors automatically and print results to the UART console.
3. Monitor the output in your serial terminal. Expected behaviour after bug fixes: all tests should pass.

## ILA Debug Setup

To capture waveforms when the 0xFF pattern is sent, follow these steps:

### 1. Prepare the ILA Core in Vivado
- Ensure your Vivado project includes an ILA core connected to the AES‑128’s AXI‑Stream interface signals (`s_axis_tdata`, `tvalid`, `tready`, `tlast`, etc.).
- Set up a suitable trigger condition. Two useful examples:
  - **Trigger on any data:** `s_axis_tdata != 0`
  - **Trigger on back‑pressure:** `s_axis_tvalid == 1 && s_axis_tready == 0`

### 2. Set a Breakpoint in Vitis
- In the source code, find the `run_vector()` function that sends the 0xFF pattern. Inside it, locate the call to `wait_for_ila_setup()`.
- Double‑click the left margin to set a breakpoint on that line.

### 3. Launch the Debug Session
- In Vitis, select **Debug As → Launch on Hardware**.
- The program will run and halt at the breakpoint **before** the DMA transfer for the 0xFF block begins.

### 4. Arm the ILA in Vivado
- Switch to the Vivado Hardware Manager window.
- Select the ILA core and open the **ILA Dashboard**.
- Set your desired trigger condition (e.g., `s_axis_tdata != 0`).
- Click the **Run Trigger** button (the ILA is now armed and waiting).

### 5. Resume the Software
- Return to your serial terminal (e.g., TeraTerm). It should show a message like:
  ```
  Press any key to start 0xFF test...
  ```
- Press any key. The software will continue, initiate the DMA transfer, and the ILA will trigger when the condition is met.

### 6. Capture the Waveform
- Once triggered, the ILA will display the captured data in the Vivado waveform window.
- You can now analyse the signals, zoom in, add buses, etc.

### 7. Continue or Terminate
- After examining the waveform, you can either let the software run to completion (further tests will execute) or terminate the debug session.

## Capturing Back‑pressure Events

The test suite includes a **multi‑block test** that sends the same 16‑byte block four times in one DMA stream. To capture back‑pressure:

- Set the ILA trigger to `s_axis_tvalid == 1 && s_axis_tready == 0`.
- Follow the same procedure as above, but place the breakpoint before the multi‑block test (or simply run without breakpoint and rely on the trigger condition).
- When the core needs idle cycles, the `tvalid/tready` handshake will show the back‑pressure.

## Analyzing Results

- **Console Output:** The UART terminal prints each test vector and whether it passed or failed. After bug fixes, all tests should show **PASS**.
- **ILA Waveforms:** Verify that:
  - `tvalid` and `tready` assert correctly for each transfer.
  - `tlast` is asserted on the last byte of each block.
  - Data and key inputs match expected values.
  - Ciphertext output (from `m_axis`) matches expected after the appropriate latency.

## Troubleshooting

| Issue                          | Possible Solution                                                                          |
|--------------------------------|--------------------------------------------------------------------------------------------|
| No UART output                 | Check baud rate (115200) and serial port. Re‑plug USB cable.                               |
| Breakpoint not hit             | Ensure the correct line is breakpointed. Rebuild project if code changed.                  |
| ILA does not trigger           | Verify trigger condition matches actual signals. Increase sample depth.                    |
| FPGA not programming           | Check JTAG connection, jumpers, and power. Try reprogramming from Vivado.                  |
| Tests still fail after bug fix | Re‑verify hardware design (timing, resets). Use ILA to inspect handshake and data paths.   |

---

This guide should help you successfully run the AES‑128 test suite and leverage ILA for in‑depth debugging. For any further issues, consult the Vivado/Vitis documentation or your hardware design files.