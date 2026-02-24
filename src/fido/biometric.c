#include "biometric.h"

#ifdef ESP_PLATFORM
#include "r302.h"
#include "pico_keys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include <string.h>

typedef enum {
    BIO_CMD_VERIFY = 0,
    BIO_CMD_ENROLL,
    BIO_CMD_REMOVE,
    BIO_CMD_WIPE,
} bio_cmd_type_t;

typedef struct {
    bio_cmd_type_t type;
    uint32_t timeout_ms;
    uint16_t id;
} bio_cmd_t;

static QueueHandle_t bio_cmd_q = NULL;
static QueueHandle_t bio_evt_q = NULL;
static TaskHandle_t bio_task_handle = NULL;
static bool bio_supported = false;
static uint16_t bio_template_count = 0;
static bool bio_slot_cache_valid = false;
static uint8_t bio_slot_used[BIO_TEMPLATE_SLOT_COUNT] = { 0 };
static volatile bool bio_cancel_requested = false;
static bio_event_t bio_last_event = { .type = BIO_EVT_NONE, .match_id = 0, .sensor_code = 0 };

static bool bio_update_template_count(void) {
    uint16_t count = 0;
    if (r302_get_template_count(&count) == R302_OK) {
        bio_template_count = count;
        return true;
    }
    return false;
}

static void bio_invalidate_slot_cache(void) {
    bio_slot_cache_valid = false;
}

static bool bio_refresh_slot_cache(void) {
    if (!bio_supported) {
        return false;
    }
    if (!bio_update_template_count()) {
        return false;
    }

    memset(bio_slot_used, 0, sizeof(bio_slot_used));
    if (bio_template_count == 0) {
        bio_slot_cache_valid = true;
        return true;
    }

    uint16_t found = 0;
    for (uint16_t id = 0; id < BIO_TEMPLATE_SLOT_COUNT && found < bio_template_count; id++) {
        uint8_t ret = r302_load_model(id);
        if (ret == R302_OK) {
            bio_slot_used[id] = 1;
            found++;
        }
        else if (ret != R302_NOTFOUND &&
                 ret != R302_BADLOCATION &&
                 ret != R302_DBRANGEFAIL &&
                 ret != R302_PACKETRECIEVEERR) {
            // R302 firmware variants can return different non-OK codes for empty slots.
            // Keep scanning and log unusual responses instead of failing enumerate.
            printf("[bio] load_model(%u) during scan -> 0x%02x\n", (unsigned)id, ret);
        }
        vTaskDelay(pdMS_TO_TICKS(8));
    }

    if (found != bio_template_count) {
        bio_template_count = found;
    }
    bio_slot_cache_valid = true;
    return true;
}

static bool bio_wait_for_finger(uint32_t timeout_ms) {
    uint8_t ret = 0;
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);
    while ((xTaskGetTickCount() - start_tick) < timeout_ticks) {
        if (bio_cancel_requested) {
            return false;
        }
        ret = r302_get_image();
        if (ret == R302_OK) {
            return true;
        }
        if (ret != R302_NOFINGER && ret != R302_PACKETRECIEVEERR) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    return false;
}

static bool bio_wait_for_finger_off(uint32_t timeout_ms) {
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);
    while ((xTaskGetTickCount() - start_tick) < timeout_ticks) {
        if (bio_cancel_requested) {
            return false;
        }
        if (r302_get_image() == R302_NOFINGER) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    return false;
}

static bio_event_t bio_run_verify(uint32_t timeout_ms) {
    bio_event_t evt = { .type = BIO_EVT_VERIFY_TIMEOUT, .match_id = 0, .sensor_code = 0 };
    uint8_t error_streak = 0;
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start_tick) < timeout_ticks) {
        if (bio_cancel_requested) {
            evt.type = BIO_EVT_CANCELLED;
            return evt;
        }

        uint8_t ret = r302_get_image();
        if (ret == R302_NOFINGER) {
            vTaskDelay(pdMS_TO_TICKS(30));
            continue;
        }
        if (ret != R302_OK) {
            evt.sensor_code = ret;
            error_streak++;
            if (error_streak >= 5) {
                evt.type = BIO_EVT_VERIFY_ERROR;
                return evt;
            }
            vTaskDelay(pdMS_TO_TICKS(60));
            continue;
        }

        error_streak = 0;
        ret = r302_image2tz(1);
        if (ret != R302_OK) {
            evt.sensor_code = ret;
            vTaskDelay(pdMS_TO_TICKS(80));
            continue;
        }

        uint16_t match_id = 0, score = 0;
        ret = r302_finger_fast_search(&match_id, &score);
        if (ret == R302_OK) {
            evt.type = BIO_EVT_VERIFY_MATCH;
            evt.match_id = match_id;
            return evt;
        }
        if (ret == R302_NOMATCH || ret == R302_NOTFOUND) {
            evt.type = BIO_EVT_VERIFY_NO_MATCH;
            evt.sensor_code = ret;
            if (!bio_wait_for_finger_off(1500)) {
                return evt;
            }
            continue;
        }
        evt.type = BIO_EVT_VERIFY_ERROR;
        evt.sensor_code = ret;
        return evt;
    }

    evt.type = BIO_EVT_VERIFY_TIMEOUT;
    return evt;
}

static bio_event_t bio_run_enroll(uint16_t id, uint32_t timeout_ms) {
    (void)timeout_ms;
    bio_event_t evt = { .type = BIO_EVT_ENROLL_FAIL, .match_id = 0, .sensor_code = 0 };
    if (id >= BIO_TEMPLATE_SLOT_COUNT) {
        evt.sensor_code = R302_BADLOCATION;
        return evt;
    }

    if (!bio_wait_for_finger(10000)) {
        evt.type = BIO_EVT_VERIFY_TIMEOUT;
        return evt;
    }
    uint8_t ret = r302_image2tz(1);
    if (ret != R302_OK) {
        evt.sensor_code = ret;
        return evt;
    }

    if (!bio_wait_for_finger_off(8000)) {
        evt.type = BIO_EVT_VERIFY_TIMEOUT;
        return evt;
    }

    if (!bio_wait_for_finger(10000)) {
        evt.type = BIO_EVT_VERIFY_TIMEOUT;
        return evt;
    }
    ret = r302_image2tz(2);
    if (ret != R302_OK) {
        evt.sensor_code = ret;
        return evt;
    }

    ret = r302_create_model();
    if (ret != R302_OK) {
        evt.sensor_code = ret;
        return evt;
    }

    ret = r302_store_model(id);
    if (ret != R302_OK) {
        evt.sensor_code = ret;
        return evt;
    }

    bio_update_template_count();
    bio_invalidate_slot_cache();
    evt.type = BIO_EVT_ENROLL_OK;
    return evt;
}

static bio_event_t bio_run_remove(uint16_t id) {
    bio_event_t evt = { .type = BIO_EVT_REMOVE_FAIL, .match_id = 0, .sensor_code = 0 };
    if (id >= BIO_TEMPLATE_SLOT_COUNT) {
        evt.sensor_code = R302_BADLOCATION;
        return evt;
    }
    uint8_t ret = r302_delete_model(id);
    if (ret == R302_OK) {
        bio_update_template_count();
        bio_invalidate_slot_cache();
        evt.type = BIO_EVT_REMOVE_OK;
        return evt;
    }
    evt.sensor_code = ret;
    return evt;
}

static bio_event_t bio_run_wipe(void) {
    bio_event_t evt = { .type = BIO_EVT_WIPE_FAIL, .match_id = 0, .sensor_code = 0 };
    if (r302_empty_database() == R302_OK) {
        bio_template_count = 0;
        memset(bio_slot_used, 0, sizeof(bio_slot_used));
        bio_slot_cache_valid = true;
        evt.type = BIO_EVT_WIPE_OK;
    }
    return evt;
}

static void bio_task(void *arg) {
    (void)arg;
    bio_cmd_t cmd;
    for (;;) {
        if (xQueueReceive(bio_cmd_q, &cmd, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        bio_event_t evt = { .type = BIO_EVT_VERIFY_ERROR, .match_id = 0, .sensor_code = 0 };
        if (!bio_supported) {
            evt.type = BIO_EVT_VERIFY_ERROR;
            xQueueSend(bio_evt_q, &evt, 0);
            continue;
        }

        bio_cancel_requested = false;

        switch (cmd.type) {
            case BIO_CMD_VERIFY:
                evt = bio_run_verify(cmd.timeout_ms);
                break;
            case BIO_CMD_ENROLL:
                evt = bio_run_enroll(cmd.id, cmd.timeout_ms);
                break;
            case BIO_CMD_REMOVE:
                evt = bio_run_remove(cmd.id);
                break;
            case BIO_CMD_WIPE:
                evt = bio_run_wipe();
                break;
            default:
                evt.type = BIO_EVT_VERIFY_ERROR;
                break;
        }

        bio_last_event = evt;
        xQueueSend(bio_evt_q, &evt, 0);
    }
}

void bio_init(void) {
    if (bio_task_handle) {
        return;
    }

    printf("[bio] init uart=%d tx=%d rx=%d\n", (int)R302_UART_NUM, (int)R302_TX_PIN, (int)R302_RX_PIN);
    esp_err_t err = r302_init(R302_UART_NUM, R302_TX_PIN, R302_RX_PIN);
    uint8_t verify = R302_PASSFAIL;
    if (err == ESP_OK) {
        verify = r302_verify_password();
    }
    if (err == ESP_OK && verify == R302_OK) {
        bio_supported = true;
        bio_update_template_count();
        bio_invalidate_slot_cache();
        printf("[bio] sensor ready, templates=%u\n", (unsigned)bio_template_count);
    } else {
        bio_supported = false;
        printf("[bio] sensor not ready (init=%d, verify=0x%02x)\n", (int)err, verify);
    }

    bio_cmd_q = xQueueCreate(2, sizeof(bio_cmd_t));
    bio_evt_q = xQueueCreate(2, sizeof(bio_event_t));
    xTaskCreate(bio_task, "bio_task", 4096, NULL, 5, &bio_task_handle);
}

bool bio_is_supported(void) {
    return bio_supported;
}

bool bio_has_templates(void) {
    return bio_supported && bio_template_count > 0;
}

uint16_t bio_get_template_count(void) {
    return bio_template_count;
}

bio_event_t bio_get_last_event(void) {
    return bio_last_event;
}

bool bio_begin_verify(uint32_t timeout_ms) {
    if (!bio_supported || bio_cmd_q == NULL) {
        return false;
    }
    xQueueReset(bio_evt_q);
    bio_cmd_t cmd = { .type = BIO_CMD_VERIFY, .timeout_ms = timeout_ms, .id = 0 };
    return xQueueSend(bio_cmd_q, &cmd, 0) == pdTRUE;
}

bool bio_begin_enroll(uint16_t id, uint32_t timeout_ms) {
    if (!bio_supported || bio_cmd_q == NULL || id >= BIO_TEMPLATE_SLOT_COUNT) {
        return false;
    }
    xQueueReset(bio_evt_q);
    bio_cmd_t cmd = { .type = BIO_CMD_ENROLL, .timeout_ms = timeout_ms, .id = id };
    return xQueueSend(bio_cmd_q, &cmd, 0) == pdTRUE;
}

bool bio_begin_remove(uint16_t id, uint32_t timeout_ms) {
    (void)timeout_ms;
    if (!bio_supported || bio_cmd_q == NULL || id >= BIO_TEMPLATE_SLOT_COUNT) {
        return false;
    }
    xQueueReset(bio_evt_q);
    bio_cmd_t cmd = { .type = BIO_CMD_REMOVE, .timeout_ms = 0, .id = id };
    return xQueueSend(bio_cmd_q, &cmd, 0) == pdTRUE;
}

bool bio_begin_wipe(uint32_t timeout_ms) {
    (void)timeout_ms;
    if (!bio_supported || bio_cmd_q == NULL) {
        return false;
    }
    xQueueReset(bio_evt_q);
    bio_cmd_t cmd = { .type = BIO_CMD_WIPE, .timeout_ms = 0, .id = 0 };
    return xQueueSend(bio_cmd_q, &cmd, 0) == pdTRUE;
}

void bio_cancel(void) {
    bio_cancel_requested = true;
}

bool bio_wait_event(bio_event_t *out, uint32_t timeout_ms) {
    if (bio_evt_q == NULL || out == NULL) {
        return false;
    }
    return xQueueReceive(bio_evt_q, out, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

bool bio_try_get_event(bio_event_t *out) {
    if (bio_evt_q == NULL || out == NULL) {
        return false;
    }
    return xQueueReceive(bio_evt_q, out, 0) == pdTRUE;
}

bool bio_get_template_ids(uint16_t *ids, size_t max_ids, size_t *out_count) {
    if (out_count == NULL || !bio_supported || (max_ids > 0 && ids == NULL)) {
        return false;
    }
    if (!bio_slot_cache_valid && !bio_refresh_slot_cache()) {
        return false;
    }

    size_t n = 0;
    for (uint16_t id = 0; id < BIO_TEMPLATE_SLOT_COUNT && n < max_ids; id++) {
        if (bio_slot_used[id] != 0) {
            ids[n++] = id;
        }
    }
    *out_count = n;
    return true;
}

bool bio_get_next_free_template_id(uint16_t *id) {
    if (id == NULL || !bio_supported) {
        return false;
    }
    if (!bio_slot_cache_valid && !bio_refresh_slot_cache()) {
        return false;
    }

    for (uint16_t i = 0; i < BIO_TEMPLATE_SLOT_COUNT; i++) {
        if (bio_slot_used[i] == 0) {
            *id = i;
            return true;
        }
    }
    return false;
}

bool bio_template_exists(uint16_t id) {
    if (!bio_supported || id >= BIO_TEMPLATE_SLOT_COUNT) {
        return false;
    }
    if (!bio_slot_cache_valid && !bio_refresh_slot_cache()) {
        return false;
    }
    return bio_slot_used[id] != 0;
}

#else

void bio_init(void) { }

bool bio_is_supported(void) {
    return false;
}

bool bio_has_templates(void) {
    return false;
}

uint16_t bio_get_template_count(void) {
    return 0;
}

bio_event_t bio_get_last_event(void) {
    bio_event_t evt = { .type = BIO_EVT_NONE, .match_id = 0, .sensor_code = 0 };
    return evt;
}

bool bio_begin_verify(uint32_t timeout_ms) {
    (void)timeout_ms;
    return false;
}

bool bio_begin_enroll(uint16_t id, uint32_t timeout_ms) {
    (void)id;
    (void)timeout_ms;
    return false;
}

bool bio_begin_remove(uint16_t id, uint32_t timeout_ms) {
    (void)id;
    (void)timeout_ms;
    return false;
}

bool bio_begin_wipe(uint32_t timeout_ms) {
    (void)timeout_ms;
    return false;
}

void bio_cancel(void) { }

bool bio_wait_event(bio_event_t *out, uint32_t timeout_ms) {
    (void)out;
    (void)timeout_ms;
    return false;
}

bool bio_try_get_event(bio_event_t *out) {
    (void)out;
    return false;
}

bool bio_get_template_ids(uint16_t *ids, size_t max_ids, size_t *out_count) {
    (void)ids;
    (void)max_ids;
    (void)out_count;
    return false;
}

bool bio_get_next_free_template_id(uint16_t *id) {
    (void)id;
    return false;
}

bool bio_template_exists(uint16_t id) {
    (void)id;
    return false;
}

#endif
