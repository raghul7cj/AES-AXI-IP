`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 06/24/2025 10:38:46 AM
// Design Name: 
// Module Name: shiftrows
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module aes_shiftrows (
    input  wire [127:0] state_in,     // 128-bit state (4x4 matrix flattened)
    output wire [127:0] state_out     // 128-bit state after ShiftRows
);

    // No shift for Row 0
    assign state_out[127:120] = state_in[127:120]; // s0
    assign state_out[95:88]   = state_in[95:88];   // s4
    assign state_out[63:56]   = state_in[63:56];   // s8
    assign state_out[31:24]   = state_in[31:24];   // s12

    // Shift Row 1 by 1
    assign state_out[119:112] = state_in[87:80];   // s5
    assign state_out[87:80]   = state_in[55:48];   // s9
    assign state_out[55:48]   = state_in[23:16];   // s13
    assign state_out[23:16]   = state_in[119:112]; // s1

    // Shift Row 2 by 2
    assign state_out[111:104] = state_in[47:40];   // s10
    assign state_out[79:72]   = state_in[15:8];    // s14
    assign state_out[47:40]   = state_in[111:104]; // s2
    assign state_out[15:8]    = state_in[79:72];   // s6

    // Shift Row 3 by 3 (or Right 1)
    assign state_out[103:96]  = state_in[7:0];     // s15
    assign state_out[71:64]   = state_in[103:96];  // s3
    assign state_out[39:32]   = state_in[71:64];   // s7
    assign state_out[7:0]     = state_in[39:32];   // s11

endmodule

