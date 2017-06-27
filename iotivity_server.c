#include <stdbool.h>
#include <stdio.h>

#include "syscfg/syscfg.h"

#include "oic/oc_api.h"

#include <cborattr/cborattr.h>

#include "iotivity_priv.h"


#if (MYNEWT_VAL(OC_SERVER) == 1)
#if HAS_LIGHT
static bool light_state = false;

#include "qapi_status.h"
#include "qapi_tlmm.h"

#define LED_PIN 29

static void
server_set_led(int pin, int value)
{
    qapi_TLMM_Config_t tlmm;
    int status;
    static qapi_GPIO_ID_t id;
    static int initialized = 0;

    tlmm.pin = pin;
    tlmm.func = 1;
    tlmm.dir = QAPI_GPIO_OUTPUT_E;
    if (value) {
        tlmm.pull = QAPI_GPIO_PULL_UP_E;
    } else {
        tlmm.pull = QAPI_GPIO_PULL_DOWN_E;
    }
    tlmm.drive = QAPI_GPIO_16MA_E;

    if (!initialized) {
        status = qapi_TLMM_Get_Gpio_ID(&tlmm, &id);
        if (status) {
            iotivity_printf("qapi_TLMM_Get_Gpio_Id fail\n");
            return;
        }
        initialized = 1;
    }
    status = qapi_TLMM_Config_Gpio(id, &tlmm);
    if (value) {
        status = qapi_TLMM_Drive_Gpio(id, pin, QAPI_GPIO_HIGH_VALUE_E);
    } else {
        status = qapi_TLMM_Drive_Gpio(id, pin, QAPI_GPIO_LOW_VALUE_E);
    }
    if (status != 0) {
        iotivity_printf("qapi_TLMM_Drive_Gpio fail\n");
    }
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface)
{
    oc_rep_start_root_object();
    switch (interface) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
    case OC_IF_RW:
        oc_rep_set_boolean(root, state, light_state);
        break;
    default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
    iotivity_printf("GET light state\n");
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface)
{
    bool state;
    int len;
    uint16_t data_off;
    struct os_mbuf *m;
    struct cbor_attr_t attrs[] = {
        [0] = {
            .attribute = "state",
            .type = CborAttrBooleanType,
            .addr.boolean = &state,
            .dflt.boolean = false
        },
        [1] = {
        }
    };

    iotivity_printf("PUT light state\n");
    len = coap_get_payload(request->packet, &m, &data_off);
    if (cbor_read_mbuf_attrs(m, data_off, len, attrs)) {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
    } else {
        light_state = state;
        server_set_led(LED_PIN, state == true);
        oc_send_response(request, OC_STATUS_CHANGED);
    }
}
#endif

extern int sensors_compass_read(int16_t *x, int16_t *y, int16_t *z);

static void
get_compass(oc_request_t *request, oc_interface_mask_t interface)
{
    int val[3];
    int16_t x, y, z;

    sensors_compass_read(&x, &y, &z);
    val[0] = x;
    val[1] = y;
    val[2] = z;

    oc_rep_start_root_object();
    switch (interface) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
    case OC_IF_R:
        oc_rep_set_int_array(root, orientation, val, 3);
        break;
    default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
    iotivity_printf("GET compass\n");
}

extern int sensors_temp_read(int *humidity, int *temp);

static void
get_temp(oc_request_t *request, oc_interface_mask_t interface)
{
    char str[32];
    int humidity, temp;

    sensors_temp_read(&humidity, &temp);
    snprintf(str, sizeof(str), "%d.%d", temp / 10, temp % 10);

    oc_rep_start_root_object();
    switch (interface) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
    case OC_IF_R:
        oc_rep_set_text_string(root, temperature, str);
        oc_rep_set_text_string(root, units, "C");
        break;
    default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
    iotivity_printf("GET temp\n");
}

static void
get_humidity(oc_request_t *request, oc_interface_mask_t interface)
{
    char str[32];
    int humidity, temp;

    sensors_temp_read(&humidity, &temp);
    snprintf(str, sizeof(str), "%d.%d", humidity / 10, humidity % 10);

    oc_rep_start_root_object();
    switch (interface) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
    case OC_IF_R:
        oc_rep_set_text_string(root, humidity, str);
        break;
    default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
    iotivity_printf("GET humidity\n");
}

static void
register_resources(void)
{
    oc_resource_t *res;
#if HAS_LIGHT
    res = oc_new_resource("/fan/1", 1, 0);

    oc_resource_bind_resource_type(res, "oic.r.fan");
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);

    oc_resource_set_discoverable(res);
    oc_resource_set_periodic_observable(res, 2);
    oc_resource_set_request_handler(res, OC_GET, get_light);
    oc_resource_set_request_handler(res, OC_PUT, put_light);
    oc_add_resource(res);
#endif
    res = oc_new_resource("/compass", 1, 0);
    oc_resource_bind_resource_type(res, "oic.r.3");
    oc_resource_bind_resource_interface(res, OC_IF_R);
    oc_resource_set_default_interface(res, OC_IF_R);

    oc_resource_set_discoverable(res);
    oc_resource_set_periodic_observable(res, 1);
    oc_resource_set_request_handler(res, OC_GET, get_compass);
    oc_add_resource(res);

    res = oc_new_resource("/temp", 1, 0);
    oc_resource_bind_resource_type(res, "oic.r.temp");
    oc_resource_bind_resource_interface(res, OC_IF_R);
    oc_resource_set_default_interface(res, OC_IF_R);

    oc_resource_set_discoverable(res);
    oc_resource_set_periodic_observable(res, 10);
    oc_resource_set_request_handler(res, OC_GET, get_temp);
    oc_add_resource(res);

    res = oc_new_resource("/humidity", 1, 0);
    oc_resource_bind_resource_type(res, "oic.r.humid");
    oc_resource_bind_resource_interface(res, OC_IF_R);
    oc_resource_set_default_interface(res, OC_IF_R);

    oc_resource_set_discoverable(res);
    oc_resource_set_periodic_observable(res, 10);
    oc_resource_set_request_handler(res, OC_GET, get_humidity);
    oc_add_resource(res);

}
#endif /* OC_SERVER */

static void
app_init(void)
{
    oc_init_platform("Mynewt", NULL, NULL);
#if (MYNEWT_VAL(OC_CLIENT) == 1)
    oc_add_device("/oic/d", "oic.d.light", "MynewtClient", "1.0", "1.0",
                  set_device_custom_property, NULL);
#endif

#if (MYNEWT_VAL(OC_SERVER) == 1)
    oc_add_device("/oic/d", "oic.d.light", "MynewtServer", "1.0", "1.0", NULL,
                  NULL);
#endif
}

oc_handler_t ocf_handler = {
    .init = app_init,
#if (MYNEWT_VAL(OC_SERVER) == 1)
    .register_resources = register_resources,
#endif
#if (MYNEWT_VAL(OC_CLIENT) == 1)
    .requests_entry = issue_requests,
#endif
 };

void
iotivity_register_resources(void)
{
    oc_main_init(&ocf_handler);
}

