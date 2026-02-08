`timescale 1ns/1ps

module aes_round_2stage (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          sys_en,
    input  wire [127:0]  state_in,
    input  wire [127:0]  round_key,
    input  wire          sel_mix_col,

    // Standard Output
    output reg  [127:0]  state_out,

    // Debug Outputs (Registered to align with state_out)
    output reg  [127:0]  sb_out,
    output reg  [127:0]  sr_out,
    output reg  [127:0]  mc_out
);

    // Internal wires for combinational logic
    wire [127:0] sb_out_wire;
    wire [127:0] sr_out_wire;
    wire [127:0] ark_in;
    wire [127:0] ark_out;

    // ---------- Stage-0: SubBytes (BRAM provides 1-cycle latency) ----------
    // The output of this module is already registered.
    aes_subbytes_bram128 u_sub (
        .clk      (clk),
        .rst_n    (rst_n),
        .sys_en   (sys_en),
        .state_in (state_in),
        .state_sb (sb_out_wire)
    );

    // ---------- Stage-1 (combinational logic): SR -> MC (opt) -> ARK ----------
    aes_shiftrows u_sr (
        .state_in (sb_out_wire),
        .state_out(sr_out_wire)
    );

    wire [127:0] mc_in_transposed; // New wire for the transposed state
    wire [127:0] mc_out_wire;
    
//wire [127:0] mc_in_cm;

//genvar i, j;
//generate
//for (i = 0; i < 4; i = i + 1) begin : ROWS
//    for (j = 0; j < 4; j = j + 1) begin : COLS
//        // row-major idx = i*4 + j
//        // col-major idx = j*4 + i
//        assign mc_in_cm[127 - ((j*4 + i)*8) -: 8] =
//               sr_out_wire[127 - ((i*4 + j)*8) -: 8];
//    end
//end
//endgenerate


    aes_mixcolumns u_mc (
        .state_in (sr_out_wire),
        .state_out(mc_out_wire)
    );

    // Select input for AddRoundKey: bypass MixColumns for the final round
    assign ark_in  = sel_mix_col ? mc_out_wire : sr_out_wire;

    aes_addroundkey u_ark (
        .state_in (ark_in),
        .round_key(round_key),
        .state_out(ark_out)
    );

    // ---------- Stage-1 Registers ----------
    // Register all outputs at the end of the second stage to align them.
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_out <= 128'd0;
            sb_out    <= 128'd0;
            sr_out    <= 128'd0;
            mc_out    <= 128'd0;
        end else if(sys_en) begin
            state_out <= ark_out;
            sb_out    <= sb_out_wire;
            sr_out    <= sr_out_wire;
            mc_out    <= mc_out_wire;
        end
    end

endmodule
