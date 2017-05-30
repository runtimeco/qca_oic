#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

INCLUDES += 						\
	-I$(SRCDIR)/iotivity				\
	-I$(SRCDIR)/iotivity/include			\
	-I$(SRCDIR)/iotivity/src			\
	-I$(SRCDIR)/iotivity/tinycbor/include		\
	-I$(SRCDIR)/iotivity/cborattr/include		\

CSRCS += \
	iotivity/iotivity_demo.c			\
	iotivity/iotivity_compat.c			\
	iotivity/iotivity_server.c			\
	iotivity/compat/os_mbuf.c			\
	iotivity/compat/os_eventq.c			\
	iotivity/compat/os_callout.c			\
	iotivity/compat/os_mempool.c			\
	iotivity/compat/mem.c				\
	iotivity/src/api/oc_buffer.c			\
	iotivity/src/api/oc_client_api.c		\
	iotivity/src/api/oc_core_res.c			\
	iotivity/src/api/oc_discovery.c			\
	iotivity/src/api/oc_helpers.c			\
	iotivity/src/api/oc_main.c			\
	iotivity/src/api/oc_rep.c			\
	iotivity/src/api/oc_ri.c			\
	iotivity/src/api/oc_server_api.c		\
	iotivity/src/api/oc_uuid.c			\
	iotivity/src/messaging/coap/coap.c		\
	iotivity/src/messaging/coap/engine.c		\
	iotivity/src/messaging/coap/observe.c		\
	iotivity/src/messaging/coap/separate.c		\
	iotivity/src/messaging/coap/transactions.c	\
	iotivity/src/port/qca/abort.c			\
	iotivity/src/port/qca/adaptor.c			\
	iotivity/src/port/qca/ble_adaptor.c		\
	iotivity/src/port/qca/clock.c			\
	iotivity/src/port/qca/ip4_adaptor.c		\
	iotivity/src/port/qca/ip_adaptor.c		\
	iotivity/src/port/qca/log.c			\
	iotivity/src/port/qca/random.c

CSRCS += \
	iotivity/tinycbor/src/cbor_buf_reader.c			\
	iotivity/tinycbor/src/cbor_buf_writer.c			\
	iotivity/tinycbor/src/cbor_mbuf_reader.c		\
	iotivity/tinycbor/src/cbor_mbuf_writer.c		\
	iotivity/tinycbor/src/cborencoder.c			\
	iotivity/tinycbor/src/cborencoder_close_container_checked.c	\
	iotivity/tinycbor/src/cborerrorstrings.c		\
	iotivity/tinycbor/src/cborparser.c			\
	iotivity/tinycbor/src/cborparser_dup_string.c

CSRCS += \
	iotivity/cborattr/src/cborattr.c
