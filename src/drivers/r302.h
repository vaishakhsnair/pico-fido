#ifndef R302_H
#define R302_H

#include <stdint.h>
#include <stdbool.h>
#include "driver/uart.h"
#include "driver/gpio.h"

// R302 Return Codes (from Adafruit_Fingerprint.h)
#define R302_OK                 0x00
#define R302_PACKETRECIEVEERR   0x01
#define R302_NOFINGER           0x02
#define R302_IMAGEFAIL          0x03
#define R302_IMAGEMESS          0x06
#define R302_FEATUREFAIL        0x07
#define R302_NOMATCH            0x08
#define R302_NOTFOUND           0x09
#define R302_ENROLLMISMATCH     0x0A
#define R302_BADLOCATION        0x0B
#define R302_DBRANGEFAIL        0x0C
#define R302_UPLOADFEATUREFAIL  0x0D
#define R302_PACKETRESPONSEFAIL 0x0E
#define R302_UPLOADFAIL         0x0F
#define R302_DELETEFAIL         0x10
#define R302_DBCLEARFAIL        0x11
#define R302_PASSFAIL           0x13
#define R302_INVALIDIMAGE       0x15
#define R302_FLASHERR           0x18
#define R302_INVALIDREG         0x1A
#define R302_ADDRCODE           0x20
#define R302_PASSVERIFY         0x21

#define R302_STARTCODE          0xEF01

#define R302_COMMANDPACKET      0x1
#define R302_DATAPACKET         0x2
#define R302_ACKPACKET          0x7
#define R302_ENDDATAPACKET      0x8

#define R302_GETIMAGE           0x01
#define R302_IMAGE2TZ           0x02
#define R302_REGMODEL           0x05
#define R302_STORE              0x06
#define R302_LOAD               0x07
#define R302_UPLOAD             0x08
#define R302_DELETE             0x0C
#define R302_EMPTY              0x0D
#define R302_VERIFYPASSWORD     0x13
#define R302_HISPEEDSEARCH      0x1B
#define R302_TEMPLATECOUNT      0x1D

// Default pins for ESP32-S3 (can be overridden)
#ifndef R302_TX_PIN
#define R302_TX_PIN GPIO_NUM_1
#endif
#ifndef R302_RX_PIN
#define R302_RX_PIN GPIO_NUM_2
#endif

// UART Configuration
#define R302_UART_NUM UART_NUM_1
#define R302_BAUD_RATE 57600
#define R302_BUF_SIZE 256

/**
 * @brief Initialize the R302 fingerprint sensor driver.
 *
 * @param uart_num UART port number (e.g., UART_NUM_1)
 * @param tx_pin TX pin number
 * @param rx_pin RX pin number
 * @return esp_err_t ESP_OK on success
 */
esp_err_t r302_init(uart_port_t uart_num, int tx_pin, int rx_pin);

/**
 * @brief Verify password with the sensor (Handshake).
 *
 * @return uint8_t R302_OK on success
 */
uint8_t r302_verify_password(void);

/**
 * @brief Capture an image from the sensor.
 *
 * @return uint8_t R302_OK on success, or error code.
 */
uint8_t r302_get_image(void);

/**
 * @brief Convert image to character file (template) in a buffer slot.
 *
 * @param slot Slot number (1 or 2)
 * @return uint8_t R302_OK on success
 */
uint8_t r302_image2tz(uint8_t slot);

/**
 * @brief Search for a fingerprint match in the library.
 *
 * @param[out] match_id Pointer to store matched ID.
 * @param[out] match_score Pointer to store match confidence.
 * @return uint8_t R302_OK on match, R302_NOMATCH, or other error.
 */
uint8_t r302_finger_fast_search(uint16_t *match_id, uint16_t *match_score);

/**
 * @brief Create a model from character files in buffers 1 and 2.
 *
 * @return uint8_t R302_OK on success
 */
uint8_t r302_create_model(void);

/**
 * @brief Store the model in buffer 1 to flash.
 *
 * @param id Storage location ID
 * @return uint8_t R302_OK on success
 */
uint8_t r302_store_model(uint16_t id);

/**
 * @brief Load a model from flash to buffer 1.
 * 
 * @param id Storage location ID
 * @return uint8_t R302_OK on success
 */
uint8_t r302_load_model(uint16_t id);

/**
 * @brief Delete a model from flash.
 *
 * @param id Storage location ID
 * @return uint8_t R302_OK on success
 */
uint8_t r302_delete_model(uint16_t id);

/**
 * @brief Delete all models.
 *
 * @return uint8_t R302_OK on success
 */
uint8_t r302_empty_database(void);

/**
 * @brief Get the number of templates stored.
 *
 * @param[out] count Pointer to store the count
 * @return uint8_t R302_OK on success
 */
uint8_t r302_get_template_count(uint16_t *count);

/**
 * @brief High-level function to check if a finger is present and matches.
 *
 * @param[out] match_id Returns the matched ID if found.
 * @return bool true if verified, false otherwise.
 */
bool r302_verify_finger(uint16_t *match_id);

#endif // R302_H
