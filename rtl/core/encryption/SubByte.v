module aes_subbytes_bram128 (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        sys_en,
    input  wire [127:0] state_in,   // MSB-first byte ordering assumed
    output wire [127:0] state_sb
);
    wire [7:0] sb_out [15:0];

    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : SB
            // byte index mapping: adjust if your byte order differs
            wire [7:0] in_byte = state_in[127 - 8*i -: 8];
            // instantiate single-byte BRAM SBox
            aes_sbox_bram sbox_i (
                .clk  (clk),
                .rst_n(rst_n),
                .sys_en(sys_en),
                .addr (in_byte),
                .dout (sb_out[i])
            );
            assign state_sb[127 - 8*i -: 8] = sb_out[i];
        end
    endgenerate
endmodule
