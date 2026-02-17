# R302 Fingerprint Sensor Integration Plan

## Objective
Integrate R302 capacitive fingerprint sensor to:
1.  Bypass PIN requirement (User Verification).
2.  Replace "touch to accept" (User Presence).

## Hardware Setup
*   **Sensor**: R302 Fingerprint Module (UART interface).
*   **Platform**: ESP32-S3.
*   **Connections**:
    *   VCC -> 3.3V
    *   GND -> GND
    *   TX -> ESP32-S3 RX (Suggested: GPIO 2 / UART1 RX)
    *   RX -> ESP32-S3 TX (Suggested: GPIO 1 / UART1 TX)
    *   TOUCH/WAKE -> GPIO (Suggested: GPIO 3 / Optional interrupt)
    *   *Note: Pins are configurable in software due to ESP32-S3 matrix.*

## Software Architecture

### 1. R302 Driver (`src/drivers/r302.c`, `src/drivers/r302.h`)
*   **Low Level**: ESP-IDF UART driver (`driver/uart.h`).
*   **High Level**:
    *   `r302_init(uart, tx, rx)`: Initialize UART.
    *   `r302_verify()`: 
        *   `PS_GetImage`: Detect finger and capture image.
        *   `PS_GenChar`: Generate character file from image.
        *   `PS_Search`: Search fingerprint library.
        *   Returns: Match ID or Error.
    *   `r302_enroll_step(step, id)`: Handle multi-step enrollment (usually 2-3 scans).
    *   `r302_delete(id)`: Remove fingerprint.
    *   `r302_empty()`: Delete all.

### 2. Integration with FIDO Stack

#### User Presence (UP)
*   **Location**: `src/fido/fido.c` -> `check_user_presence()`.
*   **Current Logic**: Waits for button press via queue/event.
*   **New Logic**:
    *   Poll R302 (or wait for touch interrupt) in parallel with button wait.
    *   If R302 detects a valid finger (Match), treat as "Button Pressed".
    *   **Optimization**: R302 matching takes time. Should be non-blocking or fit within the timeout loop.

#### User Verification (UV)
*   **Concept**: FIDO2 UV is "something you are" or "something you know" (PIN).
*   **Implementation**:
    *   Global flag `bool g_user_verified_by_bio = false`.
    *   In `check_user_presence()`, if R302 matches:
        *   Set `g_user_verified_by_bio = true`.
        *   Return `true` (Presence confirmed).
    *   In `src/fido/cbor_make_credential.c` and `src/fido/cbor_get_assertion.c`:
        *   When constructing auth data:
            *   Set `UP` bit to 1 (always if presence checked).
            *   Set `UV` bit to 1 IF `g_user_verified_by_bio` is true OR PIN was verified.
    *   **PIN Bypass**:
        *   If `uv=true` is requested by RP (Relying Party) and we have `g_user_verified_by_bio`, we can proceed without PIN prompt.
        *   Note: "clientPin" and "bioEnroll" options in `get_info` might need adjustment.

### 3. Management Interface (Enrollment)
*   Need a way to enroll fingers.
*   **Options**:
    1.  **FIDO2 `bioEnroll` extension**: Implement CTAP 2.1 bio enrollment commands. (Complex, requires full state machine).
    2.  **Vendor Specific**: Use a custom tool or special boot mode.
    3.  **Simple Button Logic**: E.g., Long press button to enter enrollment mode (LED color change), then place finger.
*   **Recommendation**: Start with "Simple Button Logic" for MVP.
    *   Long press (5s) -> LED Blue (Enroll Mode).
    *   Place finger 3 times -> LED Green (Success) / Red (Fail).

## Implementation Steps
1.  **Driver**: Create `src/drivers/r302.[ch]`.
2.  **Hook**: Initialize driver in `main.c` / `init_fido()`.
3.  **Logic**: Modify `check_user_presence` to call `r302_verify`.
4.  **State**: Propagate verification state to FIDO response generation.
    *   **Enrollment**: Add a basic enrollment trigger (e.g., button combo).

## Debugging & Logging

### 1. Enabling Logs
*   The project uses `printf` for logging.
*   To enable detailed APDU hex dumps, define `DEBUG_APDU=1` in the CMake configuration or header.
    *   Example: Add `add_definitions(-DDEBUG_APDU=1)` to `CMakeLists.txt` for the `pico_fido` target.
*   The `pico-keys-sdk` provides `DEBUG_PAYLOAD` and `DEBUG_DATA` macros in `debug.h` which are active when `DEBUG_APDU` is set.

### 2. Viewing Logs
*   **Interface**: UART0 (Pins TX=43, RX=44 on ESP32-S3 default, or standard TX/RX on DevKits).
*   **Command**: Use the ESP-IDF monitor tool:
    ```bash
    idf.py -p /dev/ttyACM0 monitor
    ```
*   **Note**: Since the USB port is likely used for FIDO/HID traffic (TinyUSB), the console logs will be output to the *physical UART* pins. You will need a separate USB-to-UART adapter connected to the UART0 pins to see these logs if the primary USB is occupied by the device application.

