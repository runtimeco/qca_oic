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
#if (MYNEWT_VAL(OC_TRANSPORT_IP) == 1) && (MYNEWT_VAL(OC_TRANSPORT_IPV6) == 1)

#include <os/os.h>
#include <os/endian.h>

#include <qapi_socket.h>
#include <qapi_netbuf.h>
#include <qapi_ns_utils.h>
#include <qapi_ns_gen_v6.h>

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

/* link-local scoped address ff02::fd */
static const struct in6_addr coap_all_nodes_v6 = {
    .s_addr = {
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD
    }
};

STATS_SECT_START(oc_ip_stats)
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
static STATS_SECT_DECL(oc_ip_stats) oc_ip_stats;
STATS_NAME_START(oc_ip_stats)
    STATS_NAME(oc_ip_stats, iframe)
    STATS_NAME(oc_ip_stats, ibytes)
    STATS_NAME(oc_ip_stats, ierr)
    STATS_NAME(oc_ip_stats, imem)
    STATS_NAME(oc_ip_stats, oucast)
    STATS_NAME(oc_ip_stats, omcast)
    STATS_NAME(oc_ip_stats, obytes)
    STATS_NAME(oc_ip_stats, oerr)
    STATS_NAME(oc_ip_stats, omem)
STATS_NAME_END(oc_ip_stats)

/* sockets to use for coap unicast and multicast */
static int oc_ucast6 = -1;

#if (MYNEWT_VAL(OC_SERVER) == 1)
static int oc_mcast6 = -1;
#endif

static void
oc_send_buffer_ip6_int(struct os_mbuf *m, int is_mcast)
{
    struct sockaddr_in6 to;
    struct os_mbuf *n;
    struct oc_endpoint *oe;
    int rc;
    int len;
    int off;
    void *buf;

    assert(OS_MBUF_USRHDR_LEN(m) >= sizeof(struct oc_endpoint_ip));
    oe = OC_MBUF_ENDPOINT(m);
    if ((oe->oe_ip.flags & IP) == 0) {
        os_mbuf_free_chain(m);
        return;
    }
    to.sin_family = AF_INET6;
    to.sin_port = htons(oe->oe_ip.v6.port);
    to.sin_flowinfo = 0;
    to.sin_scope_id = oe->oe_ip.v6.scope;
    memcpy(&to.sin_addr, oe->oe_ip.v6.address, sizeof(to.sin_addr));

    len = OS_MBUF_PKTLEN(m);

    buf = qapi_Net_Buf_Alloc(len, QAPI_NETBUF_SYS);
    if (!buf) {
        os_mbuf_free_chain(m);
        STATS_INC(oc_ip_stats, omem);
        return;
    }
    off = 0;
    for (n = m; n; n = SLIST_NEXT(n, om_next)) {
        qapi_Net_Buf_Update(buf, off, n->om_data, n->om_len, QAPI_NETBUF_SYS);
        off += n->om_len;
    }
    os_mbuf_free_chain(m);

    STATS_INCN(oc_ip_stats, obytes, len);

    if (is_mcast) {
        /* XXXX */
        rc = qapi_sendto(oc_ucast6, buf, len, MSG_ZEROCOPYSEND,
                         (struct sockaddr *) &to, sizeof(to));
    } else {
        rc = qapi_sendto(oc_ucast6, buf, len, MSG_ZEROCOPYSEND,
                         (struct sockaddr *) &to, sizeof(to));
    }
    if (rc != len) {
        OC_LOG_ERROR("Failed to send buffer %u on itf %d: %d\n",
                     len, to.sin_scope_id, qapi_errno(oc_ucast6));
        STATS_INC(oc_ip_stats, oerr);
    }
}

void
oc_send_buffer_ip6(struct os_mbuf *m)
{
    STATS_INC(oc_ip_stats, oucast);
    oc_send_buffer_ip6_int(m, 0);
}

void
oc_send_buffer_ip6_mcast(struct os_mbuf *m)
{
    STATS_INC(oc_ip_stats, omcast);
    oc_send_buffer_ip6_int(m, 1);
}

static int32_t
oc_ip_rx_callback(void *so, void *pkt, int32_t errcode, void *from,
  int32_t family)
{
    struct os_mbuf *m;
    struct oc_endpoint *oe;
    struct sockaddr_in6 *sin;
    struct qapi_Net_Buf_s *qns = (struct qapi_Net_Buf_s *)pkt;

    if (!pkt) {
        STATS_INC(oc_ip_stats, ierr);
        return -1;
    }
    if (family != AF_INET6) {
        STATS_INC(oc_ip_stats, ierr);
        return -1;
    }

    m = os_msys_get_pkthdr(0, sizeof(struct oc_endpoint_ip));
    if (!m) {
        STATS_INC(oc_ip_stats, imem);
        return -1;
    }
    oe = OC_MBUF_ENDPOINT(m);
    sin = (struct sockaddr_in6 *)from;

    oe->oe_ip.flags = IP;
    memcpy(&oe->oe_ip.v6.address, &sin->sin_addr, sizeof(oe->oe_ip.v6.address));
    oe->oe_ip.v6.scope = sin->sin_scope_id;
    oe->oe_ip.v6.port = ntohs(sin->sin_port);

    STATS_INC(oc_ip_stats, iframe);
    STATS_INCN(oc_ip_stats, ibytes, qns->nb_Plen);

    os_mbuf_copyinto(m, 0, qns->nb_Prot, qns->nb_Plen);
    qapi_Net_Buf_Free(pkt, QAPI_NETBUF_SYS);

    oc_recv_message(m);

    return 0;
}

void
oc_connectivity_shutdown_ip6(void)
{
    if (oc_ucast6 >= 0) {
        qapi_socketclose(oc_ucast6);
	oc_ucast6 = -1;
    }

#if (MYNEWT_VAL(OC_SERVER) == 1)
    if (oc_mcast6 >= 0) {
        qapi_socketclose(oc_mcast6);
	oc_mcast6 = -1;
    }
#endif
}

int
oc_connectivity_init_ip6(void)
{
    int rc;
    int i;
    int cnt;
    struct sockaddr_in6 sin;
    struct ipv6_mreq mreq;
    qapi_Net_Ifnameindex_t if_arr[4];
    int32_t scope_id;

    OC_LOG_INFO("oic: oc_connectivity_init_ip6()\n");
    oc_ucast6 = qapi_socket(AF_INET6, SOCK_DGRAM, 0);
    if (oc_ucast6 < 0) {
        OC_LOG_ERROR("Could not create oc unicast socket\n");
        return -1;
    }

#if (MYNEWT_VAL(OC_SERVER) == 1)
    oc_mcast6 = qapi_socket(AF_INET6, SOCK_DGRAM, 0);
    if (oc_mcast6 < 0) {
        qapi_socketclose(oc_ucast6);
        oc_ucast6 = -1;
        OC_LOG_ERROR("Could not create oc multicast socket\n");
        return -1;
    }
#endif

    sin.sin_family = AF_INET6;
    sin.sin_port = 0;
    sin.sin_flowinfo = 0;
    sin.sin_scope_id = 0;
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));

    rc = qapi_bind(oc_ucast6, (struct sockaddr *)&sin, sizeof(sin));
    if (rc != 0) {
        OC_LOG_ERROR("Could not bind oc unicast socket\n");
        goto oc_connectivity_init_err;
    }

    rc = qapi_setsockopt(oc_ucast6, IPPROTO_IP, SO_UDPCALLBACK,
                         (void *)oc_ip_rx_callback, 0);
    if (rc != 0) {
        OC_LOG_ERROR("Could not set udp callback\n");
        goto oc_connectivity_init_err;
    }

#if (MYNEWT_VAL(OC_SERVER) == 1)
    sin.sin_port = htons(COAP_PORT_UNSECURED);
    rc = qapi_bind(oc_mcast6, (struct sockaddr *)&sin, sizeof(sin));
    if (rc != 0) {
        OC_LOG_ERROR("Could not bind oc multicast socket %d\n", rc);
        goto oc_connectivity_init_err;
    }

    cnt = qapi_Net_Get_All_Ifnames(if_arr);
    assert(cnt < sizeof(if_arr) / sizeof(if_arr[0]));

    memset(&mreq, 0, sizeof(mreq));
    memcpy(mreq.ipv6mr_multiaddr.s_addr, coap_all_nodes_v6.s_addr,
           sizeof(coap_all_nodes_v6));

    for (i = 0; i < cnt; i++) {
        qapi_Net_IPv6_Get_Scope_ID(if_arr[i].interface_Name, &scope_id);
        mreq.ipv6mr_interface = scope_id;
        if (qapi_setsockopt(oc_mcast6, IPPROTO_IP, IPV6_JOIN_GROUP, &mreq,
            sizeof(mreq))) {
            OC_LOG_DEBUG("Could not join mcast group %s %d\n",
                         if_arr[i].interface_Name, rc);
            continue;
        }
        OC_LOG_DEBUG("Joined Coap mcast group on %s\n",
	             if_arr[i].interface_Name);
    }

    rc = qapi_setsockopt(oc_mcast6, IPPROTO_IP, SO_UDPCALLBACK,
                         (void *)oc_ip_rx_callback, 0);
    if (rc != 0) {
        OC_LOG_ERROR("Could not set udp callback %d\n", rc);
        goto oc_connectivity_init_err;
    }
#endif

    (void)stats_init_and_reg(STATS_HDR(oc_ip_stats),
      STATS_SIZE_INIT_PARMS(oc_ip_stats, STATS_SIZE_32),
      STATS_NAME_INIT_PARMS(oc_ip_stats), "oc_ip6");

    return 0;

oc_connectivity_init_err:
    oc_connectivity_shutdown();
    return rc;
}

#endif
