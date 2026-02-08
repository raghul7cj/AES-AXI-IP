`timescale 1ns / 1ps

module axi_aes_ip #(
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_S_AXI_ADDR_WIDTH = 7,
    parameter integer C_AXIS_TDATA_WIDTH = 128,
    parameter integer NR = 10,
    parameter integer AES_LATENCY = 21 // Adjusted to match your pipeline depth
)(
    input  wire aclk,
    input  wire aresetn,

    // ================= AXI-Stream Slave (Encrypt) =================
    input  wire [C_AXIS_TDATA_WIDTH-1:0] s00_axis_tdata,
    input  wire                          s00_axis_tvalid,
    output wire                          s00_axis_tready,
    input  wire                          s00_axis_tlast,

    // ================= AXI-Stream Slave (Decrypt) =================
    input  wire [C_AXIS_TDATA_WIDTH-1:0] s01_axis_tdata,
    input  wire                          s01_axis_tvalid,
    output wire                          s01_axis_tready,
    input  wire                          s01_axis_tlast,

    // ================= AXI-Stream Master (Encrypt out) =================
    output wire [C_AXIS_TDATA_WIDTH-1:0] m00_axis_tdata,
    output wire                          m00_axis_tvalid,
    input  wire                          m00_axis_tready,
    output wire                          m00_axis_tlast,

    // ================= AXI-Stream Master (Decrypt out) =================
    output wire [C_AXIS_TDATA_WIDTH-1:0] m01_axis_tdata,
    output wire                          m01_axis_tvalid,
    input  wire                          m01_axis_tready,
    output wire                          m01_axis_tlast,

    // ================= AXI-Lite Slave =================
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] s_axi_awaddr,
    input  wire                          s_axi_awvalid,
    output reg                           s_axi_awready,

    input  wire [C_S_AXI_DATA_WIDTH-1:0] s_axi_wdata,
    input  wire                          s_axi_wvalid,
    output reg                           s_axi_wready,

    output wire [1:0]                    s_axi_bresp,
    output reg                           s_axi_bvalid,
    input  wire                          s_axi_bready,

    input  wire [C_S_AXI_ADDR_WIDTH-1:0] s_axi_araddr,
    input  wire                          s_axi_arvalid,
    output reg                           s_axi_arready,

    output reg  [C_S_AXI_DATA_WIDTH-1:0] s_axi_rdata,
    output wire [1:0]                    s_axi_rresp,
    output reg                           s_axi_rvalid,
    input  wire                          s_axi_rready
);

    // ============================================================
    // Register File Definitions
    // ============================================================
    reg [127:0] cipher_key_reg;
    reg [1:0]   mode;
    reg         load_new_key_pulse;
    wire        done_key_expansion;
    wire        key_is_valid;

    // ============================================================
    // WRITE CHANNEL FSM & LOGIC
    // ============================================================
    localparam [1:0] IDLE      = 2'b00;
    localparam [1:0] WAIT_ADDR = 2'b01;
    localparam [1:0] WAIT_DATA = 2'b10;
    localparam [1:0] BRESP     = 2'b11;

    reg [1:0] w_state;
    reg [1:0] w_next_state;

    reg        aw_captured;
    reg        w_captured;
    reg [31:0] awaddr_buffer;
    reg [31:0] wdata_buffer;
    reg        write_en; 

    // Internal wires for write logic
    wire [31:0] target_addr;
    wire [31:0] target_data;

    assign target_addr = aw_captured ? awaddr_buffer : s_axi_awaddr;
    assign target_data = w_captured  ? wdata_buffer  : s_axi_wdata;

    // --- Sequential Block: State & Capture ---
    always @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            w_state       <= IDLE;
            aw_captured   <= 1'b0;
            w_captured    <= 1'b0;
            awaddr_buffer <= 32'b0;
            wdata_buffer  <= 32'b0;
            
            // Reset Internal Registers
            cipher_key_reg <= 128'b0;
            mode           <= 2'b00;
        end else begin
            w_state <= w_next_state;

            // Capture Address
            if (s_axi_awvalid && s_axi_awready) begin
                awaddr_buffer <= s_axi_awaddr;
                aw_captured   <= 1'b1;
            end
            
            // Capture Data
            if (s_axi_wvalid && s_axi_wready) begin
                wdata_buffer  <= s_axi_wdata;
                w_captured    <= 1'b1;
            end

            // Clear flags when transaction finishes
            if (w_state == BRESP && s_axi_bready) begin
                aw_captured <= 1'b0;
                w_captured  <= 1'b0;
            end

            // --- REGISTER WRITE DECODE LOGIC ---
            if (write_en) begin
                case (target_addr[6:2]) 
                    5'h00: cipher_key_reg[31:0]   <= target_data; // Addr 0
                    5'h01: cipher_key_reg[63:32]  <= target_data; // Addr 1
                    5'h02: cipher_key_reg[95:64]  <= target_data; // Addr 2
                    5'h03: cipher_key_reg[127:96] <= target_data; // Addr 3
                    5'h04: mode                   <= target_data[1:0]; // Addr 4
                    default: ; 
                endcase
            end
        end
    end

    // --- Pulse Generation Logic ---
    always @(*) begin
        load_new_key_pulse = 0;
        if (write_en) begin
            // Using the wires target_addr/target_data defined above
            if (target_addr[6:2] == 5'h05 && target_data[0] == 1'b1) begin
                load_new_key_pulse = 1;
            end
        end
    end

    // --- Combinational Next State Logic ---
    always @(*) begin
        w_next_state  = w_state;
        s_axi_awready = 0;
        s_axi_wready  = 0;
        s_axi_bvalid  = 0;
        write_en      = 0;

        case (w_state)
            IDLE: begin
                s_axi_awready = 1;
                s_axi_wready  = 1;
                if (s_axi_awvalid && s_axi_wvalid) begin
                    w_next_state = BRESP;
                    write_en     = 1; 
                end else if (s_axi_awvalid) begin
                    w_next_state = WAIT_DATA;
                end else if (s_axi_wvalid) begin
                    w_next_state = WAIT_ADDR;
                end
            end
            
            WAIT_ADDR: begin
                s_axi_awready = 1;
                if (s_axi_awvalid) begin
                    w_next_state = BRESP;
                    write_en     = 1;
                end
            end

            WAIT_DATA: begin
                s_axi_wready = 1;
                if (s_axi_wvalid) begin
                    w_next_state = BRESP;
                    write_en     = 1;
                end
            end

            BRESP: begin
                s_axi_bvalid = 1;
                if (s_axi_bready) w_next_state = IDLE;
            end
            default: w_next_state = IDLE;
        endcase
    end
    assign s_axi_bresp = 2'b00; 

    // ============================================================
    // READ CHANNEL FSM & LOGIC
    // ============================================================
    localparam R_IDLE      = 1'b0;
    localparam R_SEND_DATA = 1'b1;

    reg r_state; 
    reg r_next_state;
    reg [C_S_AXI_ADDR_WIDTH-1:0] araddr_buffer_reg; 

    // --- Sequential Block ---
    always @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            r_state           <= R_IDLE;
            araddr_buffer_reg <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            r_state <= r_next_state;
            
            // Capture address exactly on handshake
            if (s_axi_arvalid && s_axi_arready) begin
                araddr_buffer_reg <= s_axi_araddr;
            end
        end
    end

    // --- Combinational Logic ---
    always @(*) begin
        r_next_state  = r_state;
        s_axi_arready = 0;
        s_axi_rvalid  = 0;

        case (r_state)
            R_IDLE: begin
                s_axi_arready = 1;
                if (s_axi_arvalid) begin
                    r_next_state = R_SEND_DATA;
                end
            end
            R_SEND_DATA: begin
                s_axi_rvalid = 1;
                if (s_axi_rready) begin 
                    r_next_state = R_IDLE;
                end
            end
            default: r_next_state = R_IDLE;
        endcase
    end

    assign s_axi_rresp = 2'b00; 

    // --- Read Data Mux ---
    wire [C_S_AXI_ADDR_WIDTH-1:0] current_raddr;
    assign current_raddr = (r_state == R_IDLE) ? s_axi_araddr : araddr_buffer_reg;

    always @(*) begin
        s_axi_rdata = 32'b0;
        case (current_raddr[6:2])
            5'h00: s_axi_rdata = cipher_key_reg[31:0];
            5'h01: s_axi_rdata = cipher_key_reg[63:32];
            5'h02: s_axi_rdata = cipher_key_reg[95:64];
            5'h03: s_axi_rdata = cipher_key_reg[127:96];
            5'h04: s_axi_rdata = {30'b0, mode};
            5'h05: s_axi_rdata = 32'b0; 
            5'h06: s_axi_rdata = {30'b0, key_is_valid, done_key_expansion};
            default: s_axi_rdata = 32'hDEADBEEF; 
        endcase
    end

    // ============================================================
    // AES Core Instance
    // ============================================================
    AES_top #(
        .NR(NR)
    ) aes_core_inst (
        .clk                (aclk),
        .rst_n              (aresetn),
        .sys_en             (pipeline_en),

        .load_new_key       (load_new_key_pulse),
        .cipher_key         (cipher_key_reg),

        // Stream Interface
        .enc_in_valid       (s00_axis_tvalid),
        .plain_text         (s00_axis_tdata),
        .enc_out_valid      (m00_axis_tvalid),
        .cipher_text_out    (m00_axis_tdata),

        .dec_in_valid       (s01_axis_tvalid),
        .cipher_text_in     (s01_axis_tdata),
        .dec_out_valid      (m01_axis_tvalid),
        .plain_text_out     (m01_axis_tdata),

        .done_key_expansion (done_key_expansion),
        .key_is_valid       (key_is_valid)
    );
    
    // Encrypt Slave Ready
    assign s00_axis_tready = m00_axis_tready && key_is_valid;

    // Decrypt Slave Ready
    assign s01_axis_tready = m01_axis_tready && key_is_valid;

    // ============================================================
    // ROBUST TLAST SHIFT REGISTER
    // ============================================================
    
    reg [AES_LATENCY-1:0] tlast_sr_enc;
    wire pipeline_en;

    // 1. Define when the pipeline moves
    assign pipeline_en = m00_axis_tready; 

    // Internal wire for bubble protection logic
    wire tlast_in;
    assign tlast_in = (s00_axis_tvalid) ? s00_axis_tlast : 1'b0;

    always @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            tlast_sr_enc <= {AES_LATENCY{1'b0}};
        end 
        else if (pipeline_en) begin
            // 2. Shift Logic with Bubble Protection
            tlast_sr_enc <= {tlast_sr_enc[AES_LATENCY-2:0], tlast_in};
        end
    end

    // 3. Output Assignment
    assign m00_axis_tlast = tlast_sr_enc[AES_LATENCY-1];

endmodule