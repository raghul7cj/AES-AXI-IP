`timescale 1ns/1ps

module aes_mixcolumns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // Function to multiply by 2 in the Galois Field (GF(2^8))
    // This is equivalent to the xtime operation.
    function [7:0] mul2;
        input [7:0] b;
        // Shift left, and if the original MSB was 1, XOR with the reduction polynomial 0x1B
        mul2 = (b << 1) ^ (8'h1B & {8{b[7]}});
    endfunction

    // Function to multiply by 3 in the Galois Field (GF(2^8))
    function [7:0] mul3;
        input [7:0] b;
        // mul3(b) is equivalent to (mul2(b) XOR b)
        mul3 = mul2(b) ^ b;
    endfunction

    // --- Column 0 Processing ---
    wire [7:0] s00 = state_in[127:120];
    wire [7:0] s10 = state_in[119:112];
    wire [7:0] s20 = state_in[111:104];
    wire [7:0] s30 = state_in[103:96];

    assign state_out[127:120] = mul2(s00) ^ mul3(s10) ^ s20       ^ s30;
    assign state_out[119:112] = s00       ^ mul2(s10) ^ mul3(s20) ^ s30;
    assign state_out[111:104] = s00       ^ s10       ^ mul2(s20) ^ mul3(s30);
    assign state_out[103:96]  = mul3(s00) ^ s10       ^ s20       ^ mul2(s30);

    // --- Column 1 Processing ---
    wire [7:0] s01 = state_in[95:88];
    wire [7:0] s11 = state_in[87:80];
    wire [7:0] s21 = state_in[79:72];
    wire [7:0] s31 = state_in[71:64];

    assign state_out[95:88] = mul2(s01) ^ mul3(s11) ^ s21       ^ s31;
    assign state_out[87:80] = s01       ^ mul2(s11) ^ mul3(s21) ^ s31;
    assign state_out[79:72] = s01       ^ s11       ^ mul2(s21) ^ mul3(s31);
    assign state_out[71:64] = mul3(s01) ^ s11       ^ s21       ^ mul2(s31);

    // --- Column 2 Processing ---
    wire [7:0] s02 = state_in[63:56];
    wire [7:0] s12 = state_in[55:48];
    wire [7:0] s22 = state_in[47:40];
    wire [7:0] s32 = state_in[39:32];

    assign state_out[63:56] = mul2(s02) ^ mul3(s12) ^ s22       ^ s32;
    assign state_out[55:48] = s02       ^ mul2(s12) ^ mul3(s22) ^ s32;
    assign state_out[47:40] = s02       ^ s12       ^ mul2(s22) ^ mul3(s32);
    assign state_out[39:32] = mul3(s02) ^ s12       ^ s22       ^ mul2(s32);

    // --- Column 3 Processing ---
    wire [7:0] s03 = state_in[31:24];
    wire [7:0] s13 = state_in[23:16];
    wire [7:0] s23 = state_in[15:8];
    wire [7:0] s33 = state_in[7:0];

    assign state_out[31:24] = mul2(s03) ^ mul3(s13) ^ s23       ^ s33;
    assign state_out[23:16] = s03       ^ mul2(s13) ^ mul3(s23) ^ s33;
    assign state_out[15:8]  = s03       ^ s13       ^ mul2(s23) ^ mul3(s33);
    assign state_out[7:0]   = mul3(s03) ^ s13       ^ s23       ^ mul2(s33);

endmodule
