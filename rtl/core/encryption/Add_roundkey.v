module aes_addroundkey (
    input  wire [127:0] state_in,   // Current AES state (row-major in your design)
    input  wire [127:0] round_key,  // Round key (AES column-major order)
    output wire [127:0] state_out   // New state after AddRoundKey
);

    // Transpose state_in from row-major ? column-major
//    wire [127:0] state_in_cm;
//    genvar i, j;
//    generate
//        for (i = 0; i < 4; i = i + 1) begin : ROWS
//            for (j = 0; j < 4; j = j + 1) begin : COLS
//                // row-major idx = i*4 + j, col-major idx = j*4 + i
//                assign state_in_cm[127 - ((j*4 + i)*8) -: 8] =
//                        state_in[127 - ((i*4 + j)*8) -: 8];
//            end
//        end
//    endgenerate

    // Now XOR column-major state with round key
    assign state_out = state_in ^ round_key;

endmodule
