#ifndef BIOMETRIC_H
#define BIOMETRIC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BIO_EVT_NONE = 0,
    BIO_EVT_VERIFY_MATCH,
    BIO_EVT_VERIFY_NO_MATCH,
    BIO_EVT_VERIFY_TIMEOUT,
    BIO_EVT_VERIFY_ERROR,
    BIO_EVT_ENROLL_OK,
    BIO_EVT_ENROLL_FAIL,
    BIO_EVT_WIPE_OK,
    BIO_EVT_WIPE_FAIL,
    BIO_EVT_CANCELLED,
} bio_event_type_t;

typedef struct {
    bio_event_type_t type;
    uint16_t match_id;
    uint8_t sensor_code;
} bio_event_t;

void bio_init(void);
bool bio_is_supported(void);
bool bio_has_templates(void);
uint16_t bio_get_template_count(void);
bio_event_t bio_get_last_event(void);

bool bio_begin_verify(uint32_t timeout_ms);
bool bio_begin_enroll(uint16_t id, uint32_t timeout_ms);
bool bio_begin_wipe(uint32_t timeout_ms);
void bio_cancel(void);

bool bio_wait_event(bio_event_t *out, uint32_t timeout_ms);
bool bio_try_get_event(bio_event_t *out);

#ifdef __cplusplus
}
#endif

#endif // BIOMETRIC_H
