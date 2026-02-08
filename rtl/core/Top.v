module aes_unrolled_pipelined_Encrypt #(
    parameter NR = 10
) (
    input  wire           clk,
    input  wire           rst_n,
    input  wire           sys_en,
    input  wire           in_valid,
    input  wire [127:0]   plaintext,
    input  wire [(NR+1)*128-1:0] round_keys_flat,
    output wire           out_valid,
    output wire [127:0]   ciphertext
);
    localparam TOTAL_KEYS     = NR + 1;
    localparam PIPELINE_DEPTH = (NR * 2) + 1;

    // 1. Key Slicer
    wire [127:0] rk [0:TOTAL_KEYS-1];
    genvar k;
    generate
        for (k = 0; k < TOTAL_KEYS; k = k + 1) begin : KEY_SLICER
            assign rk[k] = round_keys_flat[(k*128) +: 128];
        end
    endgenerate

    reg [127:0] state_after_ark0, plaintext_r;

   always @(posedge clk or negedge rst_n) begin
       if (!rst_n) begin
           state_after_ark0 <= 128'd0;
       end else if (in_valid && sys_en) begin 
           state_after_ark0 <= plaintext_r ^ rk[0];
       end
   end
   
    always @(posedge clk or negedge rst_n) begin
       if (!rst_n) begin
           plaintext_r      <= 128'd0;
       end else if(sys_en) begin 
           plaintext_r      <= plaintext;
       end
   end

    // 4. AES Rounds
    wire [127:0] round_input [0:NR-1];
    wire [127:0] round_output [0:NR-1];
    assign round_input[0] = state_after_ark0;

    genvar r;
    generate
        for (r = 0; r < NR; r = r + 1) begin : ROUNDS_GEN
            if (r > 0) assign round_input[r] = round_output[r-1];
            localparam IS_FINAL_ROUND = (r == NR - 1);
            
            aes_round_2stage round_inst (
                .clk(clk),
                .rst_n(rst_n),
                .sys_en(sys_en),
                .state_in(round_input[r]),
                .round_key(rk[r+1]),
                .sel_mix_col(~IS_FINAL_ROUND),
                .state_out(round_output[r])
            );
        end
    endgenerate

    // 5. Valid Pipeline (Control Path)
    reg [PIPELINE_DEPTH-1:0] valid_pipe;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            valid_pipe <= {PIPELINE_DEPTH{1'b0}};
        end else if (sys_en)begin
            valid_pipe <= {valid_pipe[PIPELINE_DEPTH-2:0], in_valid};
        end
    end

    assign out_valid = valid_pipe[PIPELINE_DEPTH-1];
    assign ciphertext = round_output[NR-1];

endmodule
