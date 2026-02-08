`timescale 1ns/1ps
//////////////////////////////////////////////////////////////////////////////////
// Iterative AES expanded-key generator with final expanded key output
//////////////////////////////////////////////////////////////////////////////////
module aes_expandedkey (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        sys_en,
    input  wire        start,             // asserted to load new key
    input  wire [127:0] key,
    output wire [1407:0] expandedkey,     // round10..round0
    output reg         done               // pulses high for 1 clk when expansion is complete
);

    // FSM states
    localparam S_IDLE     = 2'b00;
    localparam S_START    = 2'b01;
    localparam S_GENERATE = 2'b10;

    reg [1:0] state, next_state;

    // registers to hold round keys 0..10
    reg [127:0] round_keys_reg [0:10];

    // round counter (0..10)
    reg [3:0] round_cnt;

    // Latency counter (to model 2-cycle expansion per round)
    reg [1:0] latency_cnt;

    // The previous key register to feed aes_key_expansion
    reg [127:0] prev_key_reg;

    // single instance output
    wire [127:0] aes_next_key;

    // output concatenation (round10 .. round0)
    assign expandedkey = { round_keys_reg[10], round_keys_reg[9], round_keys_reg[8],
                           round_keys_reg[7], round_keys_reg[6], round_keys_reg[5],
                           round_keys_reg[4], round_keys_reg[3], round_keys_reg[2],
                           round_keys_reg[1], round_keys_reg[0] };

    // key expansion primitive
    aes_key_expansion aes_inst (
        .clk      (clk),
        .rst_n    (rst_n),
        .prev_key (prev_key_reg),
        .round_idx(round_cnt),
        .next_key (aes_next_key)
    );

    // declare loop variable for init
    integer i;

    // Next-state (combinational)
    always @(*) begin
        next_state = state;
        case (state)
            S_IDLE: begin
                if (start)
                    next_state = S_START;
            end
            S_START: begin
                next_state = S_GENERATE;
            end
            S_GENERATE: begin
                if (latency_cnt == 2'd1 && round_cnt == 4'd10) begin
                    next_state = S_IDLE;
                end
            end
            default: next_state = S_IDLE;
        endcase
    end

    // State register
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            state <= S_IDLE;
        else if(sys_en)
            state <= next_state;
    end

    // Controller + datapath
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            round_cnt     <= 4'd0;
            prev_key_reg  <= 128'b0;
            done          <= 1'b0;
            latency_cnt   <= 2'd0;
            for (i = 0; i < 11; i = i + 1)
                round_keys_reg[i] <= 128'b0;
        end else begin
            done <= 1'b0; // default

            case (state)
                S_IDLE: begin
                    // do nothing
                end

                S_START: begin
                    // latch round0
                    round_keys_reg[0] <= key;
                    prev_key_reg <= key;
                    round_cnt <= 4'd1;
                    latency_cnt <= 2'd0;
                end

                S_GENERATE: begin
                    latency_cnt <= latency_cnt + 2'd1;
                    if (latency_cnt == 2'd1) begin
                        // store next round key
                        round_keys_reg[round_cnt] <= aes_next_key;
                        prev_key_reg <= aes_next_key;

                        if (round_cnt == 4'd10) begin
                            done <= 1'b1; // expansion finished
                            round_cnt <= 4'd0;
                        end else begin
                            round_cnt <= round_cnt + 4'd1;
                        end
                        latency_cnt <= 2'd0;
                    end
                end

            endcase
        end
    end

endmodule

//
// AES Key Expansion for a 128-bit key
// Generates the next round key from the previous one
//
module aes_key_expansion (
    input wire clk,
    input wire rst_n,
    input wire [127:0] prev_key,
    input wire [3:0] round_idx,
    output wire [127:0] next_key
);

    // Round Constant Table for AES-128
    reg [7:0] rcon [10:1];
    initial begin
        rcon[1] = 8'h01;
        rcon[2] = 8'h02;
        rcon[3] = 8'h04;
        rcon[4] = 8'h08;
        rcon[5] = 8'h10;
        rcon[6] = 8'h20;
        rcon[7] = 8'h40;
        rcon[8] = 8'h80;
        rcon[9] = 8'h1b;
        rcon[10] = 8'h36;
    end

    // Internal variables
    wire [31:0] w0, w1, w2, w3, w4, w5, w6, w7;
    wire [31:0] temp_word;
    wire [31:0] temp_word_rotated;
    wire [31:0] temp_word_subbed;
    // Split the previous key into words
    assign w0 = prev_key[127:96];
    assign w1 = prev_key[95:64];
    assign w2 = prev_key[63:32];
    assign w3 = prev_key[31:0];

    assign temp_word_rotated = {w3[23:0], w3[31:24]};
    // The core of the key expansion function is applied to the last word
    // This is the SubWord, RotWord, and Rcon XOR part
    aes_sub_word sub_word_inst (
        .clk(clk),.in_word(temp_word_rotated), // RotWord
        .out_word(temp_word_subbed),.rst_n(rst_n)
    );

    // Apply the XOR with the round constant
    assign w4 = w0 ^ temp_word_subbed ^ {rcon[round_idx], 24'h0};

    // Subsequent words are a simple XOR
    assign w5 = w4 ^ w1;
    assign w6 = w5 ^ w2;
    assign w7 = w6 ^ w3;

    // Combine the new words to form the next round key
    assign next_key = {w4, w5, w6, w7};

endmodule

`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 27.08.2025 01:29:03
// Design Name: 
// Module Name: aes_sub_box
// Project Name: asdfg
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



module aes_sub_word (
    input wire clk,
    input wire rst_n,
    input wire [31:0] in_word,
    output wire [31:0] out_word
);

    // Wires to hold the outputs from the four S-Box instances
    wire [7:0] sbox_out_0, sbox_out_1, sbox_out_2, sbox_out_3;

    // Instantiate four aes_sbox_bram modules
    // Each instance processes one byte of the input word
    aes_sbox_lut sbox_inst_0 (
        .clk(clk),
        .rst_n(rst_n),
        .addr(in_word[31:24]), // Most significant byte
        .dout(sbox_out_0)
    );

    aes_sbox_lut sbox_inst_1 (
        .clk(clk),
        .rst_n(rst_n),
        .addr(in_word[23:16]),
        .dout(sbox_out_1)
    );

    aes_sbox_lut sbox_inst_2 (
        .clk(clk),
        .rst_n(rst_n),
        .addr(in_word[15:8]),
        .dout(sbox_out_2)
    );

    aes_sbox_lut sbox_inst_3 (
        .clk(clk),
        .rst_n(rst_n),
        .addr(in_word[7:0]), // Least significant byte
        .dout(sbox_out_3)
    );

    // Concatenate the outputs to form the 32-bit output word
    assign out_word = {sbox_out_0, sbox_out_1, sbox_out_2, sbox_out_3};

endmodule