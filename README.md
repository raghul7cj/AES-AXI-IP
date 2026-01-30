UART-Based AES Encryption/Decryption System

1. Overview

This project implements an AES (Advanced Encryption Standard) cryptographic core interfaced with a UART module to enable secure data transmission over a serial communication channel.
Plaintext is sent via UART, encrypted using AES, and the ciphertext is transmitted back. The system also supports AES decryption for received encrypted data.

Target use case:

  i. Secure serial communication

  ii. Cryptography + digital design integration

  iii. FPGA/RTL-based hardware security demonstration|

2. Features

AES-128 encryption demonstration

UART serial communication interface

Hardware-based cryptographic processing

Synchronous RTL design(fully unrolled and pipelined for high throughput - though bottlenecked by uart )

Suitable for FPGA implementation (effecient usage of fpga resources)

<img width="1480" height="487" alt="image" src="https://github.com/user-attachments/assets/1f60b1a5-00a6-42de-b326-1b3b825ff520" />
