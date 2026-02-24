/*
 * CTAP2.1 authenticatorBioEnrollment implementation (minimal).
 */

#include "pico_keys.h"
#include "cbor.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "fido.h"
#include "files.h"
#include "apdu.h"
#include "biometric.h"
#include <string.h>
#include <stdlib.h>

#define BIO_MODALITY_FINGERPRINT 0x01
#define BIO_FINGERPRINT_KIND_TOUCH 0x01

#define BIO_CMD_ENROLL_BEGIN        0x01
#define BIO_CMD_ENROLL_CAPTURE_NEXT 0x02
#define BIO_CMD_ENROLL_CANCEL       0x03
#define BIO_CMD_ENUMERATE           0x04
#define BIO_CMD_SET_FRIENDLY_NAME   0x05
#define BIO_CMD_REMOVE              0x06
#define BIO_CMD_GET_SENSOR_INFO     0x07

#define BIO_SAMPLE_STATUS_OK        0x00
#define BIO_ENROLL_SAMPLES_REQUIRED 2
#define BIO_TEMPLATE_ID_LEN         1
#define BIO_FRIENDLY_NAME_MAX       64
#define BIO_NAMES_STORE_VERSION     1

static bool bio_enroll_pending = false;
static uint8_t bio_pending_template_id[BIO_TEMPLATE_ID_LEN] = { 0x00 };
static char bio_template_names[BIO_TEMPLATE_SLOT_COUNT][BIO_FRIENDLY_NAME_MAX] = { { 0 } };
static bool bio_template_name_set[BIO_TEMPLATE_SLOT_COUNT] = { false };
static bool bio_names_loaded = false;
static file_t *bio_names_ef = NULL;

static const uint8_t bio_names_magic[4] = { 'B', 'I', 'O', '1' };

static int bio_verify_pin_uv(uint8_t modality, uint8_t subcmd, uint8_t *raw_subpara, size_t raw_subpara_len,
                             uint64_t pinUvAuthProtocol, CborByteString pinUvAuthParam) {
    if (pinUvAuthParam.present == false || pinUvAuthParam.len == 0 || pinUvAuthProtocol == 0) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!(paut.permissions & CTAP_PERMISSION_BE)) {
        return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
    }
    if (getUserVerifiedFlagValue() == false) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    size_t payload_len = 2 + raw_subpara_len;
    uint8_t *payload = (uint8_t *)calloc(1, payload_len);
    if (!payload) {
        return CTAP2_ERR_PROCESSING;
    }
    payload[0] = modality;
    payload[1] = subcmd;
    if (raw_subpara_len > 0 && raw_subpara) {
        memcpy(payload + 2, raw_subpara, raw_subpara_len);
    }

    int ret = verify((uint8_t)pinUvAuthProtocol, paut.data, payload, (uint16_t)payload_len, pinUvAuthParam.data);
    free(payload);
    if (ret != CborNoError) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return CTAP2_OK;
}

static bool template_id_to_index(const CborByteString *templateId, uint16_t *template_idx) {
    if (templateId == NULL || template_idx == NULL) {
        return false;
    }
    if (templateId->present == false || templateId->len != BIO_TEMPLATE_ID_LEN || templateId->data == NULL) {
        return false;
    }
    uint16_t id = templateId->data[0];
    if (id >= BIO_TEMPLATE_SLOT_COUNT) {
        return false;
    }
    *template_idx = id;
    return true;
}

static void encode_template_info(CborEncoder *arrayEncoder, uint16_t template_idx) {
    uint8_t template_id[BIO_TEMPLATE_ID_LEN] = { (uint8_t)template_idx };
    CborEncoder mapEncoder;
    cbor_encoder_create_map(arrayEncoder, &mapEncoder, 2);
    cbor_encode_uint(&mapEncoder, 0x01);
    cbor_encode_byte_string(&mapEncoder, template_id, sizeof(template_id));
    cbor_encode_uint(&mapEncoder, 0x02);
    cbor_encode_text_stringz(&mapEncoder, bio_template_name_set[template_idx] ? bio_template_names[template_idx] : "");
    cbor_encoder_close_container(arrayEncoder, &mapEncoder);
}

static file_t *bio_get_names_ef(void) {
    if (bio_names_ef == NULL) {
        bio_names_ef = search_by_fid(EF_BIO_NAMES, NULL, SPECIFY_EF);
    }
    return bio_names_ef;
}

static void bio_clear_name_cache(void) {
    memset(bio_template_names, 0, sizeof(bio_template_names));
    memset(bio_template_name_set, 0, sizeof(bio_template_name_set));
}

static void bio_names_load(void) {
    file_t *ef = bio_get_names_ef();
    bio_clear_name_cache();
    bio_names_loaded = true;
    if (ef == NULL || !file_has_data(ef)) {
        return;
    }

    const uint8_t *data = file_get_data(ef);
    uint16_t len = file_get_size(ef);
    if (data == NULL || len < 5) {
        return;
    }
    if (memcmp(data, bio_names_magic, sizeof(bio_names_magic)) != 0 || data[4] != BIO_NAMES_STORE_VERSION) {
        return;
    }

    size_t off = 5;
    while (off + 2 <= len) {
        uint8_t id = data[off++];
        uint8_t nlen = data[off++];
        if (off + nlen > len) {
            break;
        }
        if (id < BIO_TEMPLATE_SLOT_COUNT && nlen < BIO_FRIENDLY_NAME_MAX) {
            if (nlen > 0) {
                memcpy(bio_template_names[id], data + off, nlen);
                bio_template_names[id][nlen] = '\0';
                bio_template_name_set[id] = true;
            }
        }
        off += nlen;
    }
}

static void bio_names_ensure_loaded(void) {
    if (!bio_names_loaded) {
        bio_names_load();
    }
}

static bool bio_names_save(void) {
    file_t *ef = bio_get_names_ef();
    if (ef == NULL) {
        return false;
    }
    bio_names_ensure_loaded();

    size_t needed = 5;
    for (uint16_t i = 0; i < BIO_TEMPLATE_SLOT_COUNT; i++) {
        if (!bio_template_name_set[i]) {
            continue;
        }
        size_t nlen = strnlen(bio_template_names[i], BIO_FRIENDLY_NAME_MAX - 1);
        needed += 2 + nlen;
    }

    uint8_t *buf = (uint8_t *)calloc(1, needed);
    if (buf == NULL) {
        return false;
    }
    memcpy(buf, bio_names_magic, sizeof(bio_names_magic));
    buf[4] = BIO_NAMES_STORE_VERSION;

    size_t off = 5;
    for (uint16_t i = 0; i < BIO_TEMPLATE_SLOT_COUNT; i++) {
        if (!bio_template_name_set[i]) {
            continue;
        }
        size_t nlen = strnlen(bio_template_names[i], BIO_FRIENDLY_NAME_MAX - 1);
        buf[off++] = (uint8_t)i;
        buf[off++] = (uint8_t)nlen;
        if (nlen > 0) {
            memcpy(buf + off, bio_template_names[i], nlen);
            off += nlen;
        }
    }

    int ret = file_put_data(ef, buf, (uint16_t)off);
    mbedtls_platform_zeroize(buf, needed);
    free(buf);
    if (ret == PICOKEY_OK) {
        low_flash_available();
        return true;
    }
    return false;
}

int cbor_bio_enroll(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = { 0 };
    const bool *getModality = NULL;
    uint64_t modality = 0, subcommand = 0, pinUvAuthProtocol = 0;
    uint8_t *raw_subpara = NULL;
    size_t raw_subpara_len = 0;
    uint64_t timeoutMs = 20000;
    CborByteString templateId = { 0 };
    CborCharString friendlyName = { 0 };
    size_t resp_size = 0;
    bool encoded_map = false;
    CborEncoder encoder, mapEncoder, arrayEncoder;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(modality, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x03) {
            uint64_t subpara = 0;
            raw_subpara = (uint8_t *)cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(templateId, 2);
                }
                else if (subpara == 0x02) {
                    CBOR_FIELD_GET_TEXT(friendlyName, 2);
                }
                else if (subpara == 0x03) {
                    CBOR_FIELD_GET_UINT(timeoutMs, 2);
                }
                else {
                    CBOR_ADVANCE(2);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = (size_t)(cbor_value_get_next_byte(&_f1) - raw_subpara);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x06) {
            CBOR_FIELD_GET_BOOL(getModality, 1);
        }
        else {
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);

    if (getModality == ptrue) {
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        encoded_map = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_MODALITY_FINGERPRINT));
        goto ok;
    }

    if (modality != BIO_MODALITY_FINGERPRINT) {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    if (!bio_is_supported()) {
        CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
    }
    bio_names_ensure_loaded();

    bool auth_required = true;
    if (subcommand == BIO_CMD_ENROLL_CANCEL || subcommand == BIO_CMD_GET_SENSOR_INFO) {
        auth_required = false;
    }
    if (auth_required) {
        int verify_ret = bio_verify_pin_uv((uint8_t)modality, (uint8_t)subcommand, raw_subpara, raw_subpara_len,
                                           pinUvAuthProtocol, pinUvAuthParam);
        if (verify_ret != CTAP2_OK) {
            CBOR_ERROR(verify_ret);
        }
    }

    if (subcommand == BIO_CMD_ENROLL_BEGIN) {
        uint16_t template_idx = 0;
        if (!bio_get_next_free_template_id(&template_idx)) {
            CBOR_ERROR(CTAP2_ERR_FP_DATABASE_FULL);
        }
        bio_pending_template_id[0] = (uint8_t)template_idx;
        bio_enroll_pending = true;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 3));
        encoded_map = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, bio_pending_template_id, sizeof(bio_pending_template_id)));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_SAMPLE_STATUS_OK));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_ENROLL_SAMPLES_REQUIRED));
    }
    else if (subcommand == BIO_CMD_ENROLL_CAPTURE_NEXT) {
        if (!bio_enroll_pending) {
            CBOR_ERROR(CTAP2_ERR_NO_OPERATIONS);
        }
        if (timeoutMs > 60000) {
            timeoutMs = 60000;
        }

        bio_event_t evt = { 0 };
        if (!bio_begin_enroll((uint16_t)bio_pending_template_id[0], (uint32_t)timeoutMs)) {
            bio_enroll_pending = false;
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        }
        if (!bio_wait_event(&evt, (uint32_t)(timeoutMs + 5000)) || evt.type != BIO_EVT_ENROLL_OK) {
            bio_enroll_pending = false;
            if (evt.type == BIO_EVT_VERIFY_TIMEOUT) {
                CBOR_ERROR(CTAP2_ERR_USER_ACTION_TIMEOUT);
            }
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        }

        bio_template_name_set[bio_pending_template_id[0]] = false;
        memset(bio_template_names[bio_pending_template_id[0]], 0, BIO_FRIENDLY_NAME_MAX);
        (void)bio_names_save();
        bio_enroll_pending = false;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        encoded_map = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_SAMPLE_STATUS_OK));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0));
    }
    else if (subcommand == BIO_CMD_ENROLL_CANCEL) {
        if (!bio_enroll_pending) {
            CBOR_ERROR(CTAP2_ERR_NO_OPERATIONS);
        }
        bio_cancel();
        bio_enroll_pending = false;
        goto ok;
    }
    else if (subcommand == BIO_CMD_ENUMERATE) {
        uint16_t ids[BIO_TEMPLATE_SLOT_COUNT] = { 0 };
        size_t listed = 0;
        if (!bio_get_template_ids(ids, BIO_TEMPLATE_SLOT_COUNT, &listed)) {
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        encoded_map = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, listed));
        for (size_t i = 0; i < listed; i++) {
            encode_template_info(&arrayEncoder, ids[i]);
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));
    }
    else if (subcommand == BIO_CMD_SET_FRIENDLY_NAME) {
        uint16_t template_idx = 0;
        if (templateId.present == false || friendlyName.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (!template_id_to_index(&templateId, &template_idx) || !bio_template_exists(template_idx)) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
        if (friendlyName.len >= BIO_FRIENDLY_NAME_MAX) {
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        memcpy(bio_template_names[template_idx], friendlyName.data, friendlyName.len);
        bio_template_names[template_idx][friendlyName.len] = '\0';
        bio_template_name_set[template_idx] = true;
        (void)bio_names_save();
        goto ok;
    }
    else if (subcommand == BIO_CMD_REMOVE) {
        uint16_t template_idx = 0;
        if (templateId.present == false || templateId.len == 0) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (!template_id_to_index(&templateId, &template_idx) || !bio_template_exists(template_idx)) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
        bio_event_t evt = { 0 };
        if (!bio_begin_remove(template_idx, 2000) || !bio_wait_event(&evt, 3000) || evt.type != BIO_EVT_REMOVE_OK) {
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        }
        if (bio_enroll_pending && bio_pending_template_id[0] == template_idx) {
            bio_enroll_pending = false;
        }
        bio_template_name_set[template_idx] = false;
        memset(bio_template_names[template_idx], 0, BIO_FRIENDLY_NAME_MAX);
        (void)bio_names_save();
        goto ok;
    }
    else if (subcommand == BIO_CMD_GET_SENSOR_INFO) {
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 3));
        encoded_map = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_FINGERPRINT_KIND_TOUCH));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_ENROLL_SAMPLES_REQUIRED));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, BIO_FRIENDLY_NAME_MAX - 1));
    }
    else {
        CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
    }

ok:
    if (encoded_map) {
        CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
        resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    }
    else {
        resp_size = 0;
    }

err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(templateId);
    CBOR_FREE_BYTE_STRING(friendlyName);

    if (error == CborErrorImproperValue) {
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (error != CborNoError) {
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
