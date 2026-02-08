`timescale 1ns / 1ps

module aes_inv_mixcolumns(
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    // --- Galois Field Multiplication Functions for Inverse ---

    // Helper function: multiply by 2 (xtime)
    function [7:0] mul2;
        input [7:0] b;
        mul2 = (b << 1) ^ (8'h1B & {8{b[7]}});
    endfunction

    // Helper function: multiply by 4
    function [7:0] mul4;
        input [7:0] b;
        mul4 = mul2(mul2(b));
    endfunction

    // Helper function: multiply by 8
    function [7:0] mul8;
        input [7:0] b;
        mul8 = mul2(mul4(b));
    endfunction

    // Function to multiply by 0x09 (9)
    function [7:0] mul9;
        input [7:0] b;
        mul9 = mul8(b) ^ b;
    endfunction

    // Function to multiply by 0x0B (11)
    function [7:0] mul11;
        input [7:0] b;
        mul11 = mul8(b) ^ mul2(b) ^ b;
    endfunction

    // Function to multiply by 0x0D (13)
    function [7:0] mul13;
        input [7:0] b;
        mul13 = mul8(b) ^ mul4(b) ^ b;
    endfunction

    // Function to multiply by 0x0E (14)
    function [7:0] mul14;
        input [7:0] b;
        mul14 = mul8(b) ^ mul4(b) ^ mul2(b);
    endfunction

    // --- Column 0 Processing ---
    wire [7:0] s00 = state_in[127:120];
    wire [7:0] s10 = state_in[119:112];
    wire [7:0] s20 = state_in[111:104];
    wire [7:0] s30 = state_in[103:96];

    assign state_out[127:120] = mul14(s00) ^ mul11(s10) ^ mul13(s20) ^ mul9(s30);
    assign state_out[119:112] = mul9(s00)  ^ mul14(s10) ^ mul11(s20) ^ mul13(s30);
    assign state_out[111:104] = mul13(s00) ^ mul9(s10)  ^ mul14(s20) ^ mul11(s30);
    assign state_out[103:96]  = mul11(s00) ^ mul13(s10) ^ mul9(s20)  ^ mul14(s30);

    // --- Column 1 Processing ---
    wire [7:0] s01 = state_in[95:88];
    wire [7:0] s11 = state_in[87:80];
    wire [7:0] s21 = state_in[79:72];
    wire [7:0] s31 = state_in[71:64];

    assign state_out[95:88] = mul14(s01) ^ mul11(s11) ^ mul13(s21) ^ mul9(s31);
    assign state_out[87:80] = mul9(s01)  ^ mul14(s11) ^ mul11(s21) ^ mul13(s31);
    assign state_out[79:72] = mul13(s01) ^ mul9(s11)  ^ mul14(s21) ^ mul11(s31);
    assign state_out[71:64] = mul11(s01) ^ mul13(s11) ^ mul9(s21)  ^ mul14(s31);

    // --- Column 2 Processing ---
    wire [7:0] s02 = state_in[63:56];
    wire [7:0] s12 = state_in[55:48];
    wire [7:0] s22 = state_in[47:40];
    wire [7:0] s32 = state_in[39:32];

    assign state_out[63:56] = mul14(s02) ^ mul11(s12) ^ mul13(s22) ^ mul9(s32);
    assign state_out[55:48] = mul9(s02)  ^ mul14(s12) ^ mul11(s22) ^ mul13(s32);
    assign state_out[47:40] = mul13(s02) ^ mul9(s12)  ^ mul14(s22) ^ mul11(s32);
    assign state_out[39:32] = mul11(s02) ^ mul13(s12) ^ mul9(s22)  ^ mul14(s32);

    // --- Column 3 Processing ---
    wire [7:0] s03 = state_in[31:24];
    wire [7:0] s13 = state_in[23:16];
    wire [7:0] s23 = state_in[15:8];
    wire [7:0] s33 = state_in[7:0];

    assign state_out[31:24] = mul14(s03) ^ mul11(s13) ^ mul13(s23) ^ mul9(s33);
    assign state_out[23:16] = mul9(s03)  ^ mul14(s13) ^ mul11(s23) ^ mul13(s33);
    assign state_out[15:8]  = mul13(s03) ^ mul9(s13)  ^ mul14(s23) ^ mul11(s33);
    assign state_out[7:0]   = mul11(s03) ^ mul13(s13) ^ mul9(s23)  ^ mul14(s33);

endmodule