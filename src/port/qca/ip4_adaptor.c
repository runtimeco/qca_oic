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
#include <assert.h>
#include <string.h>

#include <syscfg/syscfg.h>
#include "port/qca/config.h"
#if (MYNEWT_VAL(OC_TRANSPORT_IP) == 1) && (MYNEWT_VAL(OC_TRANSPORT_IPV4) == 1)

#include <os/os.h>
#include <os/endian.h>

#include <qapi_socket.h>
#include <qapi_netbuf.h>
#include <qapi_ns_utils.h>
#include <qapi_netservices.h>
#include <qapi_ns_gen_v4.h>

#include <log/log.h>
#include <stats/stats.h>

#include "port/oc_connectivity.h"
#include "oic/oc_log.h"
#include "api/oc_buffer.h"
#include "port/qca/adaptor.h"

#ifdef OC_SECURITY
#error This implementation does not yet support security
#endif

#define COAP_PORT_UNSECURED (5683)

/* 224.0.1.187 */
static const struct in_addr coap_all_nodes_v4 = {
    .s_addr = htonl(0xe00001bb)
};

STATS_SECT_START(oc_ip4_stats)
    STATS_SECT_ENTRY(iframe)
    STATS_SECT_ENTRY(ibytes)
    STATS_SECT_ENTRY(ierr)
    STATS_SECT_ENTRY(imem)
    STATS_SECT_ENTRY(oucast)
    STATS_SECT_ENTRY(omcast)
    STATS_SECT_ENTRY(obytes)
    STATS_SECT_ENTRY(oerr)
    STATS_SECT_ENTRY(omem)
STATS_SECT_END
STATS_SECT_DECL(oc_ip4_stats) oc_ip4_stats;
STATS_NAME_START(oc_ip4_stats)
    STATS_NAME(oc_ip4_stats, iframe)
    STATS_NAME(oc_ip4_stats, ibytes)
    STATS_NAME(oc_ip4_stats, ierr)
    STATS_NAME(oc_ip4_stats, imem)
    STATS_NAME(oc_ip4_stats, oucast)
    STATS_NAME(oc_ip4_stats, omcast)
    STATS_NAME(oc_ip4_stats, obytes)
    STATS_NAME(oc_ip4_stats, oerr)
    STATS_NAME(oc_ip4_stats, omem)
STATS_NAME_END(oc_ip4_stats)

/* sockets to use for coap unicast and multicast */
static int oc_ucast4 = -1;

#if (MYNEWT_VAL(OC_SERVER) == 1)
static int oc_mcast4 = -1;
#endif

static void
oc_send_buffer_ip4_int(struct os_mbuf *m, int is_mcast)
{
    struct sockaddr_in to;
    struct os_mbuf *n;
    struct oc_endpoint *oe;
    int rc;
    int len;
    int off;
    void *buf;

    assert(OS_MBUF_USRHDR_LEN(m) >= sizeof(struct oc_endpoint_ip));
    oe = OC_MBUF_ENDPOINT(m);
    if ((oe->oe_ip.flags & IP4) == 0) {
        os_mbuf_free_chain(m);
        return;
    }
    to.sin_family = AF_INET;
    to.sin_port = htons(oe->oe_ip.v4.port);
    memcpy(&to.sin_addr, oe->oe_ip.v4.address, sizeof(to.sin_addr));

    len = OS_MBUF_PKTLEN(m);

    buf = qapi_Net_Buf_Alloc(len, QAPI_NETBUF_SYS);
    if (!buf) {
        os_mbuf_free_chain(m);
        STATS_INC(oc_ip4_stats, omem);
        return;
    }
    off = 0;
    for (n = m; n; n = SLIST_NEXT(n, om_next)) {
        qapi_Net_Buf_Update(buf, off, n->om_data, n->om_len, QAPI_NETBUF_SYS);
        off += n->om_len;
    }
    os_mbuf_free_chain(m);
    STATS_INCN(oc_ip4_stats, obytes, len);

    if (is_mcast) {
        rc = qapi_sendto(oc_ucast4, buf, len, MSG_ZEROCOPYSEND,
                         (struct sockaddr *)&to, sizeof(to));
    } else {
        rc = qapi_sendto(oc_ucast4, buf, len, MSG_ZEROCOPYSEND,
                         (struct sockaddr *)&to, sizeof(to));
    }
    if (rc != len) {
        OC_LOG_ERROR("Failed to send buffer %u : %d\n",
                     len, qapi_errno(oc_ucast4));
        STATS_INC(oc_ip4_stats, oerr);
    }
}

void
oc_send_buffer_ip4(struct os_mbuf *m)
{
    STATS_INC(oc_ip4_stats, oucast);
    oc_send_buffer_ip4_int(m, 0);
}
void
oc_send_buffer_ip4_mcast(struct os_mbuf *m)
{
    STATS_INC(oc_ip4_stats, omcast);
    oc_send_buffer_ip4_int(m, 1);
}

static int32_t
oc_ip4_rx_callback(void *so, void *pkt, int32_t errcode, void *from,
  int32_t family)
{
    struct os_mbuf *m;
    struct oc_endpoint *oe;
    struct sockaddr_in *sin;
    struct qapi_Net_Buf_s *qns = (struct qapi_netbuf_s *)pkt;

    if (!pkt) {
        STATS_INC(oc_ip4_stats, ierr);
        return -1;
    }
    if (family != AF_INET) {
        STATS_INC(oc_ip4_stats, ierr);
        return -1;
    }

    m = os_msys_get_pkthdr(0, sizeof(struct oc_endpoint_ip));
    if (!m) {
        STATS_INC(oc_ip4_stats, imem);
        return -1;
    }

    oe = OC_MBUF_ENDPOINT(m);
    sin = (struct sockaddr_in *)from;
    oe->oe_ip.flags = IP4;
    memcpy(&oe->oe_ip.v4.address, &sin->sin_addr,
           sizeof(oe->oe_ip.v4.address));
    oe->oe_ip.v4.port = ntohs(sin->sin_port);

    STATS_INC(oc_ip4_stats, iframe);
    STATS_INCN(oc_ip4_stats, ibytes, qns->nb_Plen);

    os_mbuf_copyinto(m, 0, qns->nb_Prot, qns->nb_Plen);
    qapi_Net_Buf_Free(pkt, QAPI_NETBUF_SYS);

    oc_recv_message(m);

    return 0;
}

void
oc_connectivity_shutdown_ip4(void)
{
    if (oc_ucast4 >= 0) {
        qapi_socketclose(oc_ucast4);
        oc_ucast4 = -1;
    }

#if (MYNEWT_VAL(OC_SERVER) == 1)
    if (oc_mcast4 >= 0) {
        qapi_socketclose(oc_mcast4);
        oc_mcast4 = -1;
    }
#endif
}

int
oc_connectivity_init_ip4(void)
{
    int rc;
    int i;
    int cnt;
    struct sockaddr_in sin;
    qapi_Net_Ifnameindex_t if_arr[4];
    struct ip_mreq mreq;
    uint32_t if_addr;

    OC_LOG_INFO("oic: oc_connectivity_init_ip4()\n");

    oc_ucast4 = qapi_socket(AF_INET, SOCK_DGRAM, 0);
    if (oc_ucast4 < 0) {
        OC_LOG_ERROR("Could not create oc unicast v4 socket\n");
        return -1;
    }

#if (MYNEWT_VAL(OC_SERVER) == 1)
    oc_mcast4 = qapi_socket(AF_INET, SOCK_DGRAM, 0);
    if (oc_mcast4 < 0) {
        qapi_socketclose(oc_ucast4);
        oc_ucast4 = -1;
        OC_LOG_ERROR("Could not create oc multicast v4 socket\n");
        return -1;
    }
#endif

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));

    rc = qapi_bind(oc_ucast4, (struct sockaddr *)&sin, sizeof(sin));
    if (rc != 0) {
        OC_LOG_ERROR("Could not bind oc unicast v4 socket\n");
        goto oc_connectivity_init_err;
    }

    rc = qapi_setsockopt(oc_ucast4, IPPROTO_IP, SO_UDPCALLBACK,
                         (void *)oc_ip4_rx_callback, 0);
    if (rc != 0) {
        OC_LOG_ERROR("Could not set udp callback\n");
        goto oc_connectivity_init_err;
    }

#if (MYNEWT_VAL(OC_SERVER) == 1)
    sin.sin_port = htons(COAP_PORT_UNSECURED);
    rc = qapi_bind(oc_mcast4, (struct sockaddr *)&sin, sizeof(sin));
    if (rc != 0) {
        OC_LOG_ERROR("Could not bind oc v4 multicast socket\n");
        goto oc_connectivity_init_err;
    }

    cnt = qapi_Net_Get_All_Ifnames(if_arr);
    assert(cnt < sizeof(if_arr) / sizeof(if_arr[0]));

    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.imr_multiaddr, &coap_all_nodes_v4, sizeof(coap_all_nodes_v4));

    /* Set socket option to join multicast group on all valid interfaces */
    for (i = 0; i < cnt; i++) {
        rc = qapi_Net_IPv4_Config(if_arr[i].interface_Name,
	                          QAPI_NET_IPV4CFG_QUERY_E,
                                  &if_addr, NULL, NULL);
        if (rc) {
            OC_LOG_ERROR("Could not fetch v4 address for %s\n",
                        if_arr[i].interface_Name);
            continue;
        }
        memcpy(&mreq.imr_interface, &if_addr, sizeof(if_addr));

        rc = qapi_setsockopt(oc_mcast4, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                             sizeof(mreq));
        if (rc) {
            OC_LOG_ERROR("Could not join mcast group %s %d\n",
                        if_arr[i].interface_Name, rc);
            continue;
        }
        OC_LOG_DEBUG("Joined Coap v4 mcast group on %s\n",
	             if_arr[i].interface_Name);
    }
    rc = qapi_setsockopt(oc_mcast4, IPPROTO_IP, SO_UDPCALLBACK,
                         (void *)oc_ip4_rx_callback, 0);
    if (rc != 0) {
        OC_LOG_ERROR("Could not set udp callback %d\n", rc);
        goto oc_connectivity_init_err;
    }
#endif
    (void)stats_init_and_reg(STATS_HDR(oc_ip4_stats),
      STATS_SIZE_INIT_PARMS(oc_ip4_stats, STATS_SIZE_32),
      STATS_NAME_INIT_PARMS(oc_ip4_stats), "oc_ip4");

    return 0;

oc_connectivity_init_err:
    oc_connectivity_shutdown();
    return rc;
}

#endif
