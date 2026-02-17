#include "r302.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define R302_TIMEOUT 0xFF

static uart_port_t g_uart_num = R302_UART_NUM;
static uint32_t g_address = 0xFFFFFFFF;
static uint32_t g_password = 0;

static void write_packet(uint32_t addr, uint8_t packettype, uint16_t len, uint8_t *packet) {
    uint8_t header[9];
    header[0] = (uint8_t)(R302_STARTCODE >> 8);
    header[1] = (uint8_t)R302_STARTCODE;
    header[2] = (uint8_t)(addr >> 24);
    header[3] = (uint8_t)(addr >> 16);
    header[4] = (uint8_t)(addr >> 8);
    header[5] = (uint8_t)(addr);
    header[6] = (uint8_t)packettype;
    header[7] = (uint8_t)(len >> 8);
    header[8] = (uint8_t)(len);

    uart_write_bytes(g_uart_num, (const char*)header, 9);

    uint16_t sum = (len >> 8) + (len & 0xFF) + packettype;
    if (packet != NULL && len > 2) {
        uart_write_bytes(g_uart_num, (const char*)packet, len - 2);
        for (int i = 0; i < len - 2; i++) {
            sum += packet[i];
        }
    }

    uint8_t checksum[2];
    checksum[0] = (uint8_t)(sum >> 8);
    checksum[1] = (uint8_t)sum;
    uart_write_bytes(g_uart_num, (const char*)checksum, 2);
}

static uint8_t get_reply(uint8_t packet[], uint16_t timeout_ms) {
    uint8_t reply[R302_BUF_SIZE];
    uint8_t ch = 0;
    int idx = 0;
    int state = 0;
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start_tick) < timeout_ticks) {
        if (uart_read_bytes(g_uart_num, &ch, 1, pdMS_TO_TICKS(10)) <= 0) {
            continue;
        }

        if (state == 0) {
            if (ch != (uint8_t)(R302_STARTCODE >> 8)) {
                continue;
            }
            reply[0] = ch;
            idx = 1;
            state = 1;
            continue;
        }
        if (state == 1) {
            if (ch != (uint8_t)(R302_STARTCODE & 0xFF)) {
                state = 0;
                idx = 0;
                continue;
            }
            reply[1] = ch;
            idx = 2;
            state = 2;
            continue;
        }

        reply[idx++] = ch;
        if (idx < 9) {
            continue;
        }

        uint8_t packettype = reply[6];
        uint16_t plen = ((uint16_t)reply[7] << 8) | reply[8];
        if (plen + 9 > sizeof(reply)) {
            return R302_PACKETRECIEVEERR;
        }

        int remaining = plen;
        int read_so_far = 0;
        while (read_so_far < remaining) {
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return R302_TIMEOUT;
            }
            int r = uart_read_bytes(g_uart_num, &reply[9 + read_so_far], remaining - read_so_far, pdMS_TO_TICKS(10));
            if (r > 0) {
                read_so_far += r;
            }
        }

        uint16_t sum = (reply[7] + reply[8] + packettype);
        for (int i = 0; i < plen - 2; i++) {
            sum += reply[9 + i];
        }
        uint16_t checksum = ((uint16_t)reply[9 + plen - 2] << 8) | reply[9 + plen - 1];
        if (sum != checksum) {
            return R302_PACKETRESPONSEFAIL;
        }

        packet[0] = packettype;
        if (plen > 2) {
            memcpy(&packet[1], &reply[9], plen - 2);
        }
        return plen - 2;
    }

    return R302_TIMEOUT;
}

static bool r302_initialized = false;

esp_err_t r302_init(uart_port_t uart_num, int tx_pin, int rx_pin) {
    if (r302_initialized) return ESP_OK;
    g_uart_num = uart_num;
    uart_config_t uart_config = {
        .baud_rate = R302_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    esp_err_t err = uart_driver_install(g_uart_num, R302_BUF_SIZE * 2, 0, 0, NULL, 0);
    if (err == ESP_ERR_INVALID_STATE) {
        // Driver already installed, proceed
        err = ESP_OK;
    }
    if (err != ESP_OK) return err;
    
    err = uart_param_config(g_uart_num, &uart_config);
    if (err != ESP_OK) return err;
    
    err = uart_set_pin(g_uart_num, tx_pin, rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) return err;

    r302_initialized = true;
    uart_flush_input(g_uart_num);
    vTaskDelay(pdMS_TO_TICKS(100)); // Delay for sensor boot
    return ESP_OK;
}

uint8_t r302_verify_password(void) {
    uint8_t packet[] = {R302_VERIFYPASSWORD, 
                      (uint8_t)(g_password >> 24), (uint8_t)(g_password >> 16),
                      (uint8_t)(g_password >> 8), (uint8_t)(g_password)};
    write_packet(g_address, R302_COMMANDPACKET, 7, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);
    
    if (len == 1 && recv_packet[0] == R302_ACKPACKET && recv_packet[1] == R302_OK)
        return R302_OK;
    return R302_PASSFAIL; 
}

uint8_t r302_get_image(void) {
    uint8_t packet[] = {R302_GETIMAGE};
    write_packet(g_address, R302_COMMANDPACKET, 3, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);
    
    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR; // or error code from packet
    return recv_packet[1];
}

uint8_t r302_image2tz(uint8_t slot) {
    uint8_t packet[] = {R302_IMAGE2TZ, slot};
    write_packet(g_address, R302_COMMANDPACKET, 4, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    return recv_packet[1];
}

uint8_t r302_create_model(void) {
    uint8_t packet[] = {R302_REGMODEL};
    write_packet(g_address, R302_COMMANDPACKET, 3, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    return recv_packet[1];
}

uint8_t r302_store_model(uint16_t id) {
    uint8_t packet[] = {R302_STORE, 0x01, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF)};
    write_packet(g_address, R302_COMMANDPACKET, 6, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    return recv_packet[1];
}

uint8_t r302_load_model(uint16_t id) {
    uint8_t packet[] = {R302_LOAD, 0x01, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF)};
    write_packet(g_address, R302_COMMANDPACKET, 6, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    return recv_packet[1];
}

uint8_t r302_delete_model(uint16_t id) {
    uint8_t packet[] = {R302_DELETE, (uint8_t)(id >> 8), (uint8_t)(id & 0xFF), 0x00, 0x01};
    write_packet(g_address, R302_COMMANDPACKET, 7, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    return recv_packet[1];
}

uint8_t r302_empty_database(void) {
    uint8_t packet[] = {R302_EMPTY};
    write_packet(g_address, R302_COMMANDPACKET, 3, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len != 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    return recv_packet[1];
}

uint8_t r302_finger_fast_search(uint16_t *match_id, uint16_t *match_score) {
    // PageID (0x0000 - 0x00A3 for 163 caps?) Adapting Adafruit default
    uint8_t packet[] = {R302_HISPEEDSEARCH, 0x01, 0x00, 0x00, 0x00, 0xA3}; 
    write_packet(g_address, R302_COMMANDPACKET, 8, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len < 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    
    if (recv_packet[1] == R302_OK) {
        if (len >= 5) {
            *match_id = ((uint16_t)recv_packet[2] << 8) | recv_packet[3];
            *match_score = ((uint16_t)recv_packet[4] << 8) | recv_packet[5];
        } else {
            return R302_PACKETRECIEVEERR;
        }
    }
    return recv_packet[1];
}

uint8_t r302_get_template_count(uint16_t *count) {
    uint8_t packet[] = {R302_TEMPLATECOUNT};
    write_packet(g_address, R302_COMMANDPACKET, 3, packet);
    uint8_t recv_packet[32];
    uint8_t len = get_reply(recv_packet, 1000);

    if (len < 1 || recv_packet[0] != R302_ACKPACKET)
        return R302_PACKETRECIEVEERR;
    
    if (recv_packet[1] == R302_OK) {
        if (len >= 3) {
            *count = ((uint16_t)recv_packet[2] << 8) | recv_packet[3];
        } else {
            return R302_PACKETRECIEVEERR;
        }
    }
    return recv_packet[1];
}

bool r302_verify_finger(uint16_t *match_id) {
    // 1. Get Image
    uint8_t ret = r302_get_image();
    if (ret != R302_OK) {
        if (ret != R302_NOFINGER) printf("verify: get_image err %02x\n", ret);
        return false;
    }
    
    // 2. Convert to char buffer 1
    if ((ret = r302_image2tz(1)) != R302_OK) {
        printf("verify: image2tz err %02x\n", ret);
        return false;
    }
    
    // 3. Search
    uint16_t score = 0;
    ret = r302_finger_fast_search(match_id, &score);
    if (ret == R302_OK) {
        printf("verify: Match found ID %d Score %d\n", *match_id, score);
        return true;
    } else {
        printf("verify: Search err %02x\n", ret);
    }
    return false;
}
