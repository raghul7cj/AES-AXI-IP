
module aes_inv_subbytes_bram128 (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [127:0] state_in,
    output wire [127:0] state_isb
);

    wire [7:0] isb_out [15:0];

    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : ISB
            wire [7:0] in_byte = state_in[127 - 8*i -: 8];

            aes_inv_sbox_bram inv_sbox_i (
                .clk  (clk),
                .rst_n(rst_n),
                .addr (in_byte),
                .dout (isb_out[i])
            );
            assign state_isb[127 - 8*i -: 8] = isb_out[i];
        end
    endgenerate
endmodule