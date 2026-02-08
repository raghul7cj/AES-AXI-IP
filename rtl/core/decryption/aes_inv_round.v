// ===============================================================
// MODULE: aes_inv_round_2stage.v
// PURPOSE: A 2-stage pipelined AES decryption round.
// UPDATED: Added registered probe outputs for debugging.
// ===============================================================
`timescale 1ns/1ps

module aes_inv_round_2stage (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          sys_en,
    input  wire [127:0]  state_in,
    input  wire [127:0]  round_key,
    input  wire          sel_inv_mix_col, // Select to perform InvMixColumns

    // Standard Output
    output reg  [127:0]  state_out,

    // Debug Probes (Registered to align with state_out)
    output reg  [127:0]  probe_isb_out,   // State after InvSubBytes
    output reg  [127:0]  probe_ark_out,   // State after AddRoundKey
    output reg  [127:0]  probe_imc_out    // State after InvMixColumns
);

    // Internal wires for the data path
    wire [127:0] isr_out_wire;
    wire [127:0] isb_out_wire;
    wire [127:0] ark_out_wire;
    wire [127:0] imc_out_wire;
    wire [127:0] final_combo_out;

    // ---------- Stage-1: InvShiftRows -> InvSubBytes ----------
    // InvShiftRows is combinational.
    aes_inv_shiftrows u_isr (
        .state_in (state_in),
        .state_out(isr_out_wire)
    );

    // InvSubBytes uses a registered BRAM, providing a 1-cycle latency.
    // Its output (isb_out_wire) is the result at the end of the first pipeline stage.
    aes_inv_subbytes_bram128 u_isb (
        .clk      (clk),
        .rst_n    (rst_n),
        .state_in (isr_out_wire),
        .state_isb(isb_out_wire)
    );

    // ---------- Stage-2: AddRoundKey -> InvMixColumns -> Final Register ----------
    aes_addroundkey u_ark (
        .state_in (isb_out_wire),
        .round_key(round_key),
        .state_out(ark_out_wire)
    );
    
    aes_inv_mixcolumns u_imc (
        .state_in (ark_out_wire),
        .state_out(imc_out_wire)
    );

    // Bypass InvMixColumns for the final round
    assign final_combo_out = sel_inv_mix_col ? imc_out_wire : ark_out_wire;

    // Register the final output and all probe signals simultaneously
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state_out     <= 128'd0;
            probe_isb_out <= 128'd0;
            probe_ark_out <= 128'd0;
            probe_imc_out <= 128'd0;
        end else if(sys_en) begin
            state_out     <= final_combo_out;
            probe_isb_out <= isb_out_wire; // Capture state after Stage 1
            probe_ark_out <= ark_out_wire; // Capture state after AddRoundKey
            probe_imc_out <= imc_out_wire; // Capture state after InvMixColumns
        end
    end

endmodule
