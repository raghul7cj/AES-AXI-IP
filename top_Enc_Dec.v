module AES_top #(
    parameter NR = 10 // Number of rounds for AES-128
) (
    clk,
    rst_n,

    // Key Interface (Shared)
    load_new_key,
    cipher_key,

    // Encryption Path
    enc_in_valid,
    plain_text,
    enc_out_valid,
    cipher_text_out,

    // Decryption Path
    dec_in_valid,
    cipher_text_in,
    dec_out_valid,
    plain_text_out,

    // Status
    done_key_expansion,
    key_is_valid
);

    //-------------------------------------------------
    // Port Declarations
    //-------------------------------------------------
    input                       clk;
    input                       rst_n;

    //-- Key Interface
    input                       load_new_key;
    input      [127:0]          cipher_key;

    //-- Encryption Path
    input                       enc_in_valid;
    input      [127:0]          plain_text;
    output                      enc_out_valid;
    output     [127:0]          cipher_text_out;

    //-- Decryption Path
    input                       dec_in_valid;
    input      [127:0]          cipher_text_in;
    output                      dec_out_valid;
    output     [127:0]          plain_text_out;

    //-- Status
    output                      done_key_expansion;
    output                      key_is_valid;

    //-------------------------------------------------
    // Internal Signals
    //-------------------------------------------------
    reg  key_is_valid;
    wire start_key_expansion;
    wire [(NR+1)*128-1:0] w_round_keys_flat;

    // Internal signals from the cores
    wire enc_core_out_valid;
    wire [127:0] enc_core_out;
    wire dec_core_out_valid;
    wire [127:0] dec_core_out;

    //-------------------------------------------------
    // Control and Key Expansion
    //-------------------------------------------------
    assign start_key_expansion = load_new_key;

    // Manage key validity
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_is_valid <= 1'b0;
        end else if (start_key_expansion) begin
            key_is_valid <= 1'b0; // invalidate immediately
        end else if (done_key_expansion) begin
            key_is_valid <= 1'b1; // set once expansion finishes
        end
    end

    // Key Expansion (shared resource)
    aes_expandedkey KEY_EXP_INST (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (start_key_expansion),
        .key        (cipher_key),
        .expandedkey(w_round_keys_flat),
        .done       (done_key_expansion)
    );

    //-------------------------------------------------
    // Encryption and Decryption Pipelines
    //-------------------------------------------------
    aes_unrolled_pipelined_Encrypt #(
        .NR(NR)
    ) INST_ENCRYPT (
        .clk             (clk),
        .rst_n           (rst_n),
        .in_valid        (enc_in_valid && key_is_valid), // ignore inputs until key valid
        .plaintext       (plain_text),
        .round_keys_flat (w_round_keys_flat),
        .out_valid       (enc_core_out_valid),
        .ciphertext      (enc_core_out)
    );

    aes_unrolled_pipelined_Decrypt #(
        .NR(NR)
    ) INST_DECRYPT (
        .clk             (clk),
        .rst_n           (rst_n),
        .in_valid        (dec_in_valid && key_is_valid), // ignore inputs until key valid
        .ciphertext      (cipher_text_in),
        .round_keys_flat (w_round_keys_flat),
        .out_valid       (dec_core_out_valid),
        .plaintext       (dec_core_out)
    );

    //-------------------------------------------------
    // Final Output Assignment (FIXED)
    //-------------------------------------------------
    // Directly pass the signals from the cores to the outputs.
    // This correctly handles the continuous data stream from the pipelines.
    assign enc_out_valid   = enc_core_out_valid;
    assign cipher_text_out = enc_core_out;

    assign dec_out_valid   = dec_core_out_valid;
    assign plain_text_out  = dec_core_out;

endmodule
