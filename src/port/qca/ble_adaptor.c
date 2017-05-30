/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <syscfg/syscfg.h>
#if (MYNEWT_VAL(OC_TRANSPORT_GATT) == 1)
#include <assert.h>
#include <os/os.h>
#include <string.h>

#include <stats/stats.h>
#include "oic/oc_gatt.h"
#include "oic/oc_log.h"
#include "messaging/coap/coap.h"
#include "api/oc_buffer.h"
#include "port/oc_connectivity.h"
#include "adaptor.h"
#include <qapi_ble.h>

#define DEVICE_NAME	"qi"
static uint32_t oc_gatt_stack_id;
static uint32_t oc_gatt_svc_id;
static uint32_t oc_gatt_gap_id;

static int oc_ble_advertise(void);

/* OIC Transport Profile GATT */

/* service UUID */
/* ADE3D529-C784-4F63-A987-EB69F70EE816 */
static qapi_BLE_GATT_Primary_Service_128_Entry_t oc_gatt_svc_primary = {
    .Service_UUID = {
	OC_GATT_SERVICE_UUID
    }
};

/* request characteristic UUID */
/* AD7B334F-4637-4B86-90B6-9D787F03D218 */
static qapi_BLE_GATT_Characteristic_Declaration_128_Entry_t
oc_gatt_req_chr_decl = {
    .Properties =
        QAPI_BLE_GATT_CHARACTERISTIC_PROPERTIES_WRITE_WITHOUT_RESPONSE |
        QAPI_BLE_GATT_CHARACTERISTIC_PROPERTIES_WRITE,
    .Characteristic_Value_UUID = {
        OC_GATT_REQ_CHAR_UUID
    }
};

static qapi_BLE_GATT_Characteristic_Value_128_Entry_t oc_gatt_req_chr_val = {
    .Characteristic_Value_UUID = {
        OC_GATT_REQ_CHAR_UUID
    },
    .Characteristic_Value_Length = 0,
    .Characteristic_Value = NULL
};

/* response characteristic UUID */
/* E9241982-4580-42C4-8831-95048216B256 */
static qapi_BLE_GATT_Characteristic_Declaration_128_Entry_t
oc_gatt_rsp_chr_decl = {
    .Properties = QAPI_BLE_GATT_CHARACTERISTIC_PROPERTIES_NOTIFY,
    .Characteristic_Value_UUID = {
        OC_GATT_RSP_CHAR_UUID
    }
};

static qapi_BLE_GATT_Characteristic_Value_128_Entry_t oc_gatt_rsp_chr_val = {
    .Characteristic_Value_UUID = {
        OC_GATT_RSP_CHAR_UUID
    },
    .Characteristic_Value_Length = 0,
    .Characteristic_Value = NULL
};

static qapi_BLE_GATT_Characteristic_Descriptor_16_Entry_t oc_gatt_rsp_chr_cfg = {
    .Characteristic_Descriptor_UUID =
    QAPI_BLE_GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_BLUETOOTH_UUID_CONSTANT,
    .Characteristic_Descriptor_Length =
         QAPI_BLE_GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_LENGTH,
    .Characteristic_Descriptor = NULL
};

static qapi_BLE_GATT_Service_Attribute_Entry_t oc_gatt_svr_svcs[] = {
    {
        .Attribute_Flags = QAPI_BLE_GATT_ATTRIBUTE_FLAGS_READABLE,
        .Attribute_Entry_Type = QAPI_BLE_AET_PRIMARY_SERVICE_128_E,
        .Attribute_Value = &oc_gatt_svc_primary
    },
    {
        .Attribute_Flags = QAPI_BLE_GATT_ATTRIBUTE_FLAGS_READABLE,
        .Attribute_Entry_Type = QAPI_BLE_AET_CHARACTERISTIC_DECLARATION_128_E,
        .Attribute_Value = &oc_gatt_req_chr_decl
    },
    {
        .Attribute_Flags = QAPI_BLE_GATT_ATTRIBUTE_FLAGS_WRITABLE,
        .Attribute_Entry_Type = QAPI_BLE_AET_CHARACTERISTIC_VALUE_128_E,
        .Attribute_Value = &oc_gatt_req_chr_val
    },
    {
        .Attribute_Flags = QAPI_BLE_GATT_ATTRIBUTE_FLAGS_READABLE,
        .Attribute_Entry_Type = QAPI_BLE_AET_CHARACTERISTIC_DECLARATION_128_E,
        .Attribute_Value = &oc_gatt_rsp_chr_decl
    },
    {
        .Attribute_Flags = 0,
        .Attribute_Entry_Type = QAPI_BLE_AET_CHARACTERISTIC_VALUE_128_E,
        .Attribute_Value = &oc_gatt_rsp_chr_val
    },
    {
        .Attribute_Flags = QAPI_BLE_GATT_ATTRIBUTE_FLAGS_READABLE_WRITABLE,
        .Attribute_Entry_Type = QAPI_BLE_AET_CHARACTERISTIC_DESCRIPTOR_16_E,
        .Attribute_Value = &oc_gatt_rsp_chr_cfg
    },
};

static uint16_t oc_gatt_svr_rsp_cfg;

#define OC_GATT_SVR_ATTR_COUNT						\
	(sizeof(oc_gatt_svr_svcs) / sizeof(oc_gatt_svr_svcs[0]))
#define OC_GATT_SVR_ATTR_REQ_OFF	2
#define OC_GATT_SVR_ATTR_RSP_OFF	4
#define OC_GATT_SVR_ATTR_RSP_CCD_OFF	5

STATS_SECT_START(oc_ble_stats)
    STATS_SECT_ENTRY(iframe)
    STATS_SECT_ENTRY(iseg)
    STATS_SECT_ENTRY(ibytes)
    STATS_SECT_ENTRY(ierr)
    STATS_SECT_ENTRY(imem)
    STATS_SECT_ENTRY(oframe)
    STATS_SECT_ENTRY(oseg)
    STATS_SECT_ENTRY(obytes)
    STATS_SECT_ENTRY(oerr)
STATS_SECT_END
STATS_SECT_DECL(oc_ble_stats) oc_ble_stats;
STATS_NAME_START(oc_ble_stats)
    STATS_NAME(oc_ble_stats, iframe)
    STATS_NAME(oc_ble_stats, iseg)
    STATS_NAME(oc_ble_stats, ibytes)
    STATS_NAME(oc_ble_stats, ierr)
    STATS_NAME(oc_ble_stats, imem)
    STATS_NAME(oc_ble_stats, oframe)
    STATS_NAME(oc_ble_stats, oseg)
    STATS_NAME(oc_ble_stats, obytes)
    STATS_NAME(oc_ble_stats, oerr)
STATS_NAME_END(oc_ble_stats)

static STAILQ_HEAD(, os_mbuf_pkthdr) oc_ble_reass_q;

#if (MYNEWT_VAL(OC_SERVER) == 1)
#endif

int
oc_ble_reass(struct os_mbuf *om1, uint16_t conn_handle)
{
    struct os_mbuf_pkthdr *pkt1;
    struct oc_endpoint_ble *oe_ble;
    struct os_mbuf *om2;
    struct os_mbuf_pkthdr *pkt2;
    uint8_t hdr[6]; /* sizeof(coap_tcp_hdr32) */

    pkt1 = OS_MBUF_PKTHDR(om1);
    assert(pkt1);

    STATS_INC(oc_ble_stats, iseg);
    STATS_INCN(oc_ble_stats, ibytes, pkt1->omp_len);

    OC_LOG_DEBUG("oc_gatt rx seg %u-%x-%u\n", conn_handle,
                 (unsigned)pkt1, pkt1->omp_len);

    STAILQ_FOREACH(pkt2, &oc_ble_reass_q, omp_next) {
        om2 = OS_MBUF_PKTHDR_TO_MBUF(pkt2);
        oe_ble = (struct oc_endpoint_ble *)OC_MBUF_ENDPOINT(om2);
        if (conn_handle == oe_ble->conn_handle) {
            /*
             * Data from same connection. Append.
             */
            os_mbuf_concat(om2, om1);
            os_mbuf_copydata(om2, 0, sizeof(hdr), hdr);

            if (coap_tcp_msg_size(hdr, sizeof(hdr)) <= pkt2->omp_len) {
                STAILQ_REMOVE(&oc_ble_reass_q, pkt2, os_mbuf_pkthdr, omp_next);
                STATS_INC(oc_ble_stats, iframe);
                oc_recv_message(om2);
            }
            pkt1 = NULL;
            break;
        }
    }
    if (pkt1) {
        /*
         * New frame, need to add oc_endpoint_ble in the front.
         * Check if there is enough space available. If not, allocate a
         * new pkthdr.
         */
        if (OS_MBUF_USRHDR_LEN(om1) < sizeof(struct oc_endpoint_ble)) {
            om2 = os_msys_get_pkthdr(0, sizeof(struct oc_endpoint_ble));
            if (!om2) {
                OC_LOG_ERROR("oc_gatt_rx: Could not allocate mbuf\n");
                STATS_INC(oc_ble_stats, ierr);
                return -1;
            }
            OS_MBUF_PKTHDR(om2)->omp_len = pkt1->omp_len;
            SLIST_NEXT(om2, om_next) = om1;
        } else {
            om2 = om1;
        }
        oe_ble = (struct oc_endpoint_ble *)OC_MBUF_ENDPOINT(om2);
        oe_ble->flags = GATT;
        oe_ble->conn_handle = conn_handle;
        pkt2 = OS_MBUF_PKTHDR(om2);

        if (os_mbuf_copydata(om2, 0, sizeof(hdr), hdr) ||
          coap_tcp_msg_size(hdr, sizeof(hdr)) > pkt2->omp_len) {
            STAILQ_INSERT_TAIL(&oc_ble_reass_q, pkt2, omp_next);
        } else {
            STATS_INC(oc_ble_stats, iframe);
            oc_recv_message(om2);
        }
    }
    return 0;
}

static void QAPI_BLE_BTPSAPI
oc_gatt_server_cb(uint32_t id,
                  qapi_BLE_GATT_Server_Event_Data_t *ev,
                  uint32_t arg)
{
    qapi_BLE_GATT_Write_Request_Data_t *wr;
    qapi_BLE_GATT_Read_Request_Data_t *rd;
    qapi_BLE_GATT_Device_Connection_MTU_Update_Data_t *mtu;
    struct os_mbuf *m;

    if (!oc_gatt_stack_id || !ev) {
        return;
    }
    OC_LOG_DEBUG("oc_gatt_server_cb(%d)\n", ev->Event_Data_Type);
    switch (ev->Event_Data_Type) {
    case QAPI_BLE_ET_GATT_SERVER_WRITE_REQUEST_E:
        wr = ev->Event_Data.GATT_Write_Request_Data;
        OC_LOG_DEBUG("oc_gatt_server_cb, write request\n");
        OC_LOG_DEBUG("  conn_id: %d\n", wr->ConnectionID);
        OC_LOG_DEBUG("  attr off: %d\n", wr->AttributeOffset);
        OC_LOG_DEBUG("  attr val len: %d\n", wr->AttributeValueLength);
        OC_LOG_DEBUG("  attr val off: %d\n", wr->AttributeValueOffset);
        OC_LOG_DEBUG("  attr val data: %p\n", wr->AttributeValue);
        OC_LOG_DEBUG("  delay write: %d\n", wr->DelayWrite);
        if (wr->AttributeOffset == OC_GATT_SVR_ATTR_REQ_OFF) {
            m = os_msys_get_pkthdr(0, sizeof(struct oc_endpoint_ble));
            if (!m) {
                OC_LOG_ERROR("oc_gatt_server_cb: Could not allocate mbuf\n");
                STATS_INC(oc_ble_stats, imem);
                break;
            }
            if (os_mbuf_copyinto(m, 0, wr->AttributeValue,
                                 wr->AttributeValueLength)) {
                OC_LOG_ERROR("oc_gatt_server_cb: Could not copy data\n");
                STATS_INC(oc_ble_stats, imem);
                break;
	    }
            if (oc_ble_reass(m, wr->ConnectionID)) {
                os_mbuf_free_chain(m);
            }
        } else if (wr->AttributeOffset == OC_GATT_SVR_ATTR_RSP_CCD_OFF &&
                   wr->AttributeValueLength == sizeof(uint16_t)) {
            memcpy(&oc_gatt_svr_rsp_cfg, wr->AttributeValue, sizeof(uint16_t));
        }
        qapi_BLE_GATT_Write_Response(oc_gatt_stack_id, wr->TransactionID);
        break;
    case QAPI_BLE_ET_GATT_SERVER_READ_REQUEST_E:
        rd = ev->Event_Data.GATT_Read_Request_Data;
        OC_LOG_DEBUG("oc_gatt_server_cb, read request\n");
        OC_LOG_DEBUG("  conn_id: %d\n", rd->ConnectionID);
        OC_LOG_DEBUG("  attr off: %d\n", rd->AttributeOffset);
        OC_LOG_DEBUG("  attr val off: %d\n", rd->AttributeValueOffset);
        if (rd->AttributeOffset == OC_GATT_SVR_ATTR_RSP_CCD_OFF) {
            qapi_BLE_GATT_Read_Response(oc_gatt_stack_id, rd->TransactionID,
              sizeof(oc_gatt_svr_rsp_cfg), (void *)&oc_gatt_svr_rsp_cfg);
        } else {
            qapi_BLE_GATT_Error_Response(oc_gatt_stack_id,
              rd->TransactionID, rd->AttributeOffset,
              QAPI_BLE_ATT_PROTOCOL_ERROR_CODE_ATTRIBUTE_NOT_LONG);
        }
        break;
    case QAPI_BLE_ET_GATT_SERVER_DEVICE_CONNECTION_E:
        OC_LOG_DEBUG("oc_gatt_server_cb, connect\n");
        break;
    case QAPI_BLE_ET_GATT_SERVER_DEVICE_DISCONNECTION_E:
        OC_LOG_DEBUG("oc_gatt_server_cb, disconnect\n");
        break;
    default:
        OC_LOG_DEBUG("oc_gatt_server_cb, other type of request %d\n",
          ev->Event_Data_Type);
        break;
    }
}

void
oc_ble_coap_conn_new(uint16_t conn_handle)
{
    OC_LOG_DEBUG("oc_gatt new conn %d\n", conn_handle);
}

void
oc_ble_coap_conn_del(uint16_t conn_handle)
{
    struct os_mbuf_pkthdr *pkt;
    struct os_mbuf *m;
    struct oc_endpoint_ble *oe_ble;

    OC_LOG_DEBUG("oc_gatt end conn %d\n", conn_handle);
    STAILQ_FOREACH(pkt, &oc_ble_reass_q, omp_next) {
        m = OS_MBUF_PKTHDR_TO_MBUF(pkt);
        oe_ble = (struct oc_endpoint_ble *)OC_MBUF_ENDPOINT(m);
        if (oe_ble->conn_handle == conn_handle) {
            STAILQ_REMOVE(&oc_ble_reass_q, pkt, os_mbuf_pkthdr, omp_next);
            os_mbuf_free_chain(m);
            break;
        }
    }
}

int
oc_connectivity_init_gatt(void)
{
    STAILQ_INIT(&oc_ble_reass_q);
    return oc_ble_coap_gatt_srv_init();
}

void
oc_connectivity_shutdown_gatt(void)
{
    /* there is not unregister for BLE */
}

static uint8_t oc_tx_buf[QAPI_BLE_GATT_DEFAULT_MAXIMUM_SUPPORTED_STACK_MTU];

void
oc_send_buffer_gatt(struct os_mbuf *m)
{
    struct oc_endpoint *oe;
    uint16_t mtu;
    uint16_t conn_handle;
    int off;
    int len;
    int rc;

    OC_LOG_DEBUG("oc_send_buffer_gatt(%d)\n", OS_MBUF_PKTLEN(m));

    assert(OS_MBUF_USRHDR_LEN(m) >= sizeof(struct oc_endpoint_ble));
    oe = OC_MBUF_ENDPOINT(m);
    conn_handle = oe->oe_ble.conn_handle;

#if (MYNEWT_VAL(OC_CLIENT) == 1)
    OC_LOG_ERROR("oc_gatt send not supported on client");
#endif

#if (MYNEWT_VAL(OC_SERVER) == 1)
    STATS_INC(oc_ble_stats, oframe);
    STATS_INCN(oc_ble_stats, obytes, OS_MBUF_PKTLEN(m));

    rc = qapi_BLE_GATT_Query_Connection_MTU(oc_gatt_stack_id, conn_handle,
                                            &mtu);
    if (rc) {
        os_mbuf_free_chain(m);
        STATS_INC(oc_ble_stats, oerr);
        return;
    }
    mtu -= 3;

    for (off = 0; off < OS_MBUF_PKTLEN(m); off += mtu) {
        STATS_INC(oc_ble_stats, oseg);

        len = min(mtu, OS_MBUF_PKTLEN(m) - off);
        os_mbuf_copydata(m, off, len, oc_tx_buf);

        rc = qapi_BLE_GATT_Handle_Value_Notification(oc_gatt_stack_id,
          oc_gatt_svc_id, conn_handle, OC_GATT_SVR_ATTR_RSP_OFF,
          len, oc_tx_buf);
        if (rc < 0) {
            OC_LOG_DEBUG("oc_send_buffer_gatt() send fail %d\n", rc);
            STATS_INC(oc_ble_stats, oerr);
            break;
        }
    }
    os_mbuf_free_chain(m);
#endif
}

static void QAPI_BLE_BTPSAPI
oc_gatt_client_cb_gaps(uint32_t id,
                       qapi_BLE_GATT_Client_Event_Data_t *ev,
                       uint32_t arg)
{
    if (!id || !ev) {
        return;
    }
    switch (ev->Event_Data_Type) {
    case QAPI_BLE_ET_GATT_CLIENT_EXCHANGE_MTU_RESPONSE_E:
        OC_LOG_DEBUG("Connection %d mtu: %d\n",
          ev->Event_Data.GATT_Exchange_MTU_Response_Data->ConnectionID,
          ev->Event_Data.GATT_Exchange_MTU_Response_Data->ServerMTU);
        break;
    default:
        break;
    }
}

static void QAPI_BLE_BTPSAPI
oc_gatt_gatt_cb(uint32_t id,
                qapi_BLE_GATT_Connection_Event_Data_t *ev,
                uint32_t arg)
{
    uint16_t mtu;
    uint32_t conn_id;

    if (!id || !ev) {
        return;
    }
    switch (ev->Event_Data_Type) {
    case QAPI_BLE_ET_GATT_CONNECTION_DEVICE_CONNECTION_E:
        conn_id = ev->Event_Data.GATT_Device_Connection_Data->ConnectionID;

        /* Attempt to update the MTU to max supported */
        if (!qapi_BLE_GATT_Query_Maximum_Supported_MTU(oc_gatt_stack_id, &mtu)){
            qapi_BLE_GATT_Exchange_MTU_Request(oc_gatt_stack_id,
              conn_id, mtu, oc_gatt_client_cb_gaps, 0);
        }
        oc_ble_coap_conn_new(conn_id);
        break;
    case QAPI_BLE_ET_GATT_CONNECTION_DEVICE_DISCONNECTION_E:
        conn_id = ev->Event_Data.GATT_Device_Disconnection_Data->ConnectionID;
        oc_ble_coap_conn_del(conn_id);
        break;
    default:
        break;
    }
}

static void QAPI_BLE_BTPSAPI
oc_gatt_gap_cb(uint32_t id, qapi_BLE_GAP_LE_Event_Data_t *ev, uint32_t arg)
{
    if (!id || !ev) {
        return;
    }
    OC_LOG_DEBUG("oc_gatt_gap_cb(%d)\n", ev->Event_Data_Type);
    switch (ev->Event_Data_Type) {
    case QAPI_BLE_ET_LE_CONNECTION_COMPLETE_E:
        OC_LOG_DEBUG("oc_gatt_gap_cb() connection complete\n");
        break;
    case QAPI_BLE_ET_LE_DISCONNECTION_COMPLETE_E:
        OC_LOG_DEBUG("oc_gatt_gap_cb() disconnected\n");
        /*
         * Disconnected. Advertise for reconnect.
         */
        oc_ble_advertise();
        break;
    default:
        break;
    }
}

static int
oc_ble_start_stack(void)
{
    static qapi_BLE_HCI_DriverInformation_t HCI_DriverInformation;
    int rc;
    uint32_t id;

    QAPI_BLE_HCI_DRIVER_SET_COMM_INFORMATION(&HCI_DriverInformation, 1, 115200,
                                             QAPI_BLE_COMM_PROTOCOL_UART_E);
    oc_gatt_stack_id = qapi_BLE_BSC_Initialize(&HCI_DriverInformation, 0);
    if ((int)oc_gatt_stack_id <= 0) {
        OC_LOG_ERROR("qapi_BLE_BSC_Initialize()=%d\n", oc_gatt_stack_id);
        return -1;
    }
    rc = qapi_BLE_GATT_Initialize(oc_gatt_stack_id,
      (QAPI_BLE_GATT_INITIALIZATION_FLAGS_SUPPORT_LE |
     QAPI_BLE_GATT_INITIALIZATION_FLAGS_DISABLE_SERVICE_CHANGED_CHARACTERISTIC),
      oc_gatt_gatt_cb, 0);
    if (rc != 0) {
        OC_LOG_ERROR("qapi_BLE_GATT_Initialize()=%d\n", rc);
        return -1;
    }

    oc_gatt_gap_id = qapi_BLE_GAPS_Initialize_Service(oc_gatt_stack_id, &id);
    if ((int)oc_gatt_gap_id <= 0) {
        OC_LOG_ERROR("qapi_BLE_GAPS_Initialied()=%d\n", oc_gatt_gap_id);
        return -1;
    }
    qapi_BLE_GAPS_Set_Device_Name(oc_gatt_stack_id, oc_gatt_gap_id,
                                  DEVICE_NAME);

    return 0;
}

static int
oc_ble_advertise(void)
{
    int rc;
    qapi_BLE_GAP_LE_Advertising_Parameters_t adv;
    qapi_BLE_GAP_LE_Connectability_Parameters_t con;
    qapi_BLE_Advertising_Data_t adv_data;
    int adv_data_len;
    int8_t txpwr;
    char dev_name[] = DEVICE_NAME;
    int len;

    memset(&adv_data, 0, sizeof(adv_data));
    adv_data.Advertising_Data[0] = 2;
    adv_data.Advertising_Data[1] =
      QAPI_BLE_HCI_LE_ADVERTISING_REPORT_DATA_TYPE_FLAGS;
    adv_data.Advertising_Data[2] =
      QAPI_BLE_HCI_LE_ADVERTISING_FLAGS_BR_EDR_NOT_SUPPORTED_FLAGS_BIT_MASK |
     QAPI_BLE_HCI_LE_ADVERTISING_FLAGS_GENERAL_DISCOVERABLE_MODE_FLAGS_BIT_MASK;
    adv_data_len = 3;

    /*
     * Transmit Power Level
     */
    if (!qapi_BLE_BSC_Query_Default_Tx_Power(oc_gatt_stack_id, FALSE, &txpwr)) {
        adv_data.Advertising_Data[adv_data_len] = 2;
        adv_data.Advertising_Data[adv_data_len + 1] =
          QAPI_BLE_HCI_LE_ADVERTISING_REPORT_DATA_TYPE_TX_POWER_LEVEL;
        adv_data.Advertising_Data[adv_data_len + 2] = txpwr;
        adv_data_len += 3;
    }

    /*
     * Device Name. XXX could place in scan response. XXX check length.
     */
    len = strlen(dev_name);
    adv_data.Advertising_Data[adv_data_len] = len + 1;
    adv_data.Advertising_Data[adv_data_len + 1] =
          QAPI_BLE_HCI_LE_ADVERTISING_REPORT_DATA_TYPE_LOCAL_NAME_COMPLETE;
    memcpy(&adv_data.Advertising_Data[adv_data_len + 2], dev_name, len);
    adv_data_len += len + 2;

    /* advertise OIC GATT service */
    adv_data.Advertising_Data[adv_data_len] = 17;
    adv_data.Advertising_Data[adv_data_len + 1] =
     QAPI_BLE_HCI_LE_ADVERTISING_REPORT_DATA_TYPE_128_BIT_SERVICE_UUID_COMPLETE;
    memcpy(&adv_data.Advertising_Data[adv_data_len + 2],
           &oc_gatt_svc_primary.Service_UUID, 16);
    adv_data_len += 18;

    rc = qapi_BLE_GAP_LE_Set_Advertising_Data(oc_gatt_stack_id, adv_data_len,
                                              &adv_data);
    if (rc != 0) {
        OC_LOG_ERROR("qapi_BLE_GAP_LE_Set_Advertising_Data() = %d\n", rc);
        return rc;
    }

    memset(&adv, 0, sizeof(adv));
    memset(&con, 0, sizeof(con));
    adv.Advertising_Interval_Min = 100;
    adv.Advertising_Interval_Max = 200;
    adv.Advertising_Channel_Map =
      QAPI_BLE_HCI_LE_ADVERTISING_CHANNEL_MAP_ENABLE_ALL_CHANNELS;
    adv.Scan_Request_Filter      = QAPI_BLE_FP_NO_FILTER_E;
    adv.Connect_Request_Filter   = QAPI_BLE_FP_NO_FILTER_E;

    con.Connectability_Mode = QAPI_BLE_LCM_CONNECTABLE_E;
    con.Own_Address_Type    = QAPI_BLE_LAT_PUBLIC_E;
    QAPI_BLE_ASSIGN_BD_ADDR(con.Direct_Address, 0, 0, 0, 0, 0, 0);

    rc = qapi_BLE_GAP_LE_Advertising_Enable(oc_gatt_stack_id, TRUE, &adv, &con,
                                            oc_gatt_gap_cb, 0);
    if (rc) {
        OC_LOG_ERROR("qapi_BLE_GAP_LE_Advertising_Enable() = %d\n", rc);
    }
    return 0;
}

int
oc_ble_coap_gatt_srv_init(void)
{
#if (MYNEWT_VAL(OC_SERVER) == 1)
    qapi_BLE_GATT_Attribute_Handle_Group_t ServiceHandleGroup;
    int rc;

    OC_LOG_INFO("oic: oc_ble_coap_gatt_svr_init()\n");
    if (oc_ble_start_stack()) {
        goto fail;
    }

    ServiceHandleGroup.Starting_Handle = 0;
    ServiceHandleGroup.Ending_Handle   = 0;

    rc = qapi_BLE_GATT_Register_Service(oc_gatt_stack_id,
      QAPI_BLE_GATT_SERVICE_FLAGS_LE_SERVICE,
      OC_GATT_SVR_ATTR_COUNT,
      oc_gatt_svr_svcs,
      &ServiceHandleGroup,
      oc_gatt_server_cb, 0);
    if (rc > 0) {
        oc_gatt_svc_id = rc;
    } else {
        OC_LOG_ERROR("qapi_BLE_GATT_Register_Service() fail - %d\n", rc);
        goto fail;
    }

    rc = oc_ble_advertise();
    if (rc) {
        // goto fail;
    }

#endif

    (void)stats_init_and_reg(STATS_HDR(oc_ble_stats),
      STATS_SIZE_INIT_PARMS(oc_ble_stats, STATS_SIZE_32),
      STATS_NAME_INIT_PARMS(oc_ble_stats), "oc_ble");
    return 0;
fail:
    return -1;
}

#endif
