`timescale 1ns / 1ps

module top (
    input  wire clk,        // 100 MHz
    input  wire rst_n,        // active-low reset
    input  wire uart_rxd,    // from PC
    output wire uart_txd,     // to PC
    output reg  done_key_expansion_r
    //output wire enc_out_valid_led
);

    wire        rx_dv;
    wire [7:0]  rx_byte;
    
    reg         tx_dv;
    reg  [7:0]  tx_byte;
    wire        tx_active;
    wire        tx_done;
    reg         load_new_key;
    reg         enc_in_valid;
    reg         dec_in_valid;
    
    reg  [127:0] plain_text;
    reg  [127:0] cipher_text_in;
    
    (* dont_touch = "yes" *) wire        enc_out_valid;
    wire        dec_out_valid;
    wire        done_key_expansion;
    
      // Add to top module port list
    assign enc_out_valid_led = enc_out_valid;
    
    (* dont_touch = "yes" *) wire [127:0] cipher_text_out;
    wire [127:0] plain_text_out;
    
    wire [127:0] cipher_key = 128'h000102030405060708090A0B0C0D0E0F;

    (* keep = "true" *) wire uart_txd_internal;
    assign uart_txd = uart_txd_internal;
    
    UART_RX #(
    .CLKS_PER_BIT(868) // 100 MHz / 115200
    ) u_uart_rx (
        .i_Rst_L   (rst_n),
        .i_Clock  (clk),
        .i_RX_Serial (uart_rxd),
        .o_RX_DV  (rx_dv),
        .o_RX_Byte(rx_byte)
    );
    
    UART_TX #(
        .CLKS_PER_BIT(868)
    ) u_uart_tx (
        .i_Rst_L    (rst_n),
        .i_Clock   (clk),
        .i_TX_DV   (tx_dv),
        .i_TX_Byte (tx_byte),
        .o_TX_Active(tx_active),
        .o_TX_Serial(uart_txd_internal),
        .o_TX_Done (tx_done)
    );
    
    
    AES_top #(
        .NR(10)
    ) u_aes (
        .clk                (clk),
        .rst_n              (rst_n),
    
        // Key interface
        .load_new_key       (load_new_key),
        .cipher_key         (cipher_key),
    
        // Encryption
        .enc_in_valid       (enc_in_valid),
        .plain_text         (plain_text),
        .enc_out_valid      (enc_out_valid),
        .cipher_text_out    (cipher_text_out),
    
        // Decryption
        .dec_in_valid       (dec_in_valid),
        .cipher_text_in     (cipher_text_in),
        .dec_out_valid      (dec_out_valid),
        .plain_text_out     (plain_text_out),
    
        // Status
        .done_key_expansion (done_key_expansion)
    );
    
    
    reg [3:0] count_bytes_rx ; // accumilate from Rx
    reg [3:0] count_bytes_tx ;
    
    reg send_plain,send;

    

    // BLOCK 1: RX Accumulation 

    reg [7:0] startup_counter;
    reg       key_loaded_flag;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            count_bytes_rx  <= 4'd0;
            plain_text      <= 128'd0;
            send            <= 1'b0;
            
            // Startup Reset Logic
            load_new_key    <= 1'b0;
            startup_counter <= 8'd0;
            key_loaded_flag <= 1'b0;
            
        end else begin
            // ---------------------------------------------------------
            // 1. SAFE KEY LOADING (Wait 200 cycles after reset)
            // ---------------------------------------------------------
            if (key_loaded_flag == 1'b0) begin
                if (startup_counter == 8'd200) begin
                    load_new_key    <= 1'b1; // Fire Pulse
                    key_loaded_flag <= 1'b1; // Mark done
                end else begin
                    startup_counter <= startup_counter + 1;
                    load_new_key    <= 1'b0;
                end
            end else begin
                load_new_key <= 1'b0; // Ensure it stays off
            end

            // 2. RX DATA LOGIC
            if (count_bytes_rx == 4'd15 && rx_dv) begin
                count_bytes_rx <= 4'b0;
                send           <= 1;
                plain_text     <= {plain_text[119:0], rx_byte};
            end else begin
                send           <= 0;
                if (rx_dv) begin
                    count_bytes_rx <= count_bytes_rx + 1;
                    plain_text <= {plain_text[119:0], rx_byte};
                end
            end
        end
    end

    reg enc_extra_pulse; // Counter to track the 2-cycle duration of i/p

    always @(posedge clk or negedge rst_n) begin //logic for sending data inside the block - 2 cycles data will be high
        if (!rst_n) begin
            enc_extra_pulse <= 0;
        end
        else begin
            if (send) begin
                enc_in_valid    <= 1;
                enc_extra_pulse <= 1;
            end else if(enc_extra_pulse) begin
                enc_in_valid    <= 1;
                enc_extra_pulse <= 0;
            end
            else begin
                enc_in_valid   <= 0;
                enc_extra_pulse <= 0;
            end
        end
    end
    
    //reg [128:0] cipher_text_out_r;
    reg send_back;

    reg [128:0] cipher_text_out_r;
    //reg send_back;

    (* keep = "true" *) reg [127:0] cipher_text_out_r;
    (* keep = "true" *) reg send_back;
    (* keep = "true" *) reg [3:0] count_bytes_tx_debug; // Renamed for clarity

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            cipher_text_out_r <= 128'b0;
            count_bytes_tx    <= 4'd0;
            tx_dv             <= 1'b0;
            tx_byte           <= 8'd0;
            send_back         <= 1'b0;
        end else begin
            // 1. DEFAULT: Pulse tx_dv LOW every cycle unless set HIGH below
            // This prevents "latch inference" which kills synthesis
            tx_dv <= 1'b0; 

            if (enc_out_valid) begin
                // START CONDITION: AES finished
                count_bytes_tx    <= 4'd0;
                cipher_text_out_r <= cipher_text_out;
                send_back         <= 1'b1;
                
                // Fire the first byte immediately
                tx_dv             <= 1'b1; 
                tx_byte           <= cipher_text_out[7:0];
            end 
            else if (send_back) begin
                // WAIT FOR UART HANDSHAKE
                if (tx_done) begin
                    if (count_bytes_tx == 4'd15) begin
                        // DONE CONDITION
                        send_back <= 1'b0;
                    end else begin
                        // NEXT BYTE CONDITION
                        count_bytes_tx    <= count_bytes_tx + 1;
                        cipher_text_out_r <= cipher_text_out_r >> 8;
                        
                        tx_dv             <= 1'b1; // Trigger next byte
                        tx_byte           <= cipher_text_out_r[15:8]; 
                    end
                end 
            end 
        end
    end

    always @(posedge clk or negedge rst_n ) begin
        if (!rst_n) begin
            done_key_expansion_r <= 0;
        end else begin
            if (done_key_expansion == 1) begin
                done_key_expansion_r <= 1;
            end else begin
                done_key_expansion_r <= done_key_expansion_r;
            end
        end
    end

endmodule