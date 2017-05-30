/*
 * XXX insert copyright here
 */
#include <stdio.h>
#include <stdlib.h>

#include <syscfg/syscfg.h>
#include "port/qca/config.h"
#include <stats/stats.h>

#include <qcli.h>
#include <qcli_api.h>

#include "iotivity_priv.h"

static int iot_running;

static QCLI_Group_Handle_t qcli_iot_grp;

static QCLI_Command_Status_t iot_start(uint32_t Parameter_Count,
                                       QCLI_Parameter_t *Parameter_List);

static QCLI_Command_Status_t iot_stats(uint32_t Parameter_Count,
                                       QCLI_Parameter_t *Parameter_List);

static QCLI_Command_Status_t iot_mem(uint32_t Parameter_Count,
                                       QCLI_Parameter_t *Parameter_List);


static const QCLI_Command_t iot_cmd_list[] = {
    {
        .Command_Function =	iot_start,
        .Start_Thread =		false,
        .Command_String =	"Start",
        .Usage_String =		"",
        .Description =		"Start OIC server"
    },
    {
        .Command_Function =	iot_stats,
        .Start_Thread =		false,
        .Command_String =	"Stats",
        .Usage_String =		"",
        .Description =		"Statistics"
    },
    {
        .Command_Function =	iot_mem,
        .Start_Thread =		false,
        .Command_String =	"Mem",
        .Usage_String =		"",
        .Description =		"Memory use"
    },
};

static const QCLI_Command_Group_t iot_cmd_group = {
    "Iotivity",
    sizeof(iot_cmd_list) / sizeof(iot_cmd_list[0]),
    iot_cmd_list
};

/*
 * Register commands with QCLI
 */
void
Initialize_Iotivity_Demo(void)
{
    qcli_iot_grp = QCLI_Register_Command_Group(NULL, &iot_cmd_group);
    if (qcli_iot_grp) {
        QCLI_Printf(qcli_iot_grp, "Iotivity registered\n");
    }
}

void
iotivity_printf(char *msg)
{
    QCLI_Printf(qcli_iot_grp, msg);
}

static QCLI_Command_Status_t
iot_start(uint32_t Parameter_Count, QCLI_Parameter_t *Parameter_List)
{
    if (iot_running) {
        return QCLI_STATUS_USAGE_E;
    }
    QCLI_Printf(qcli_iot_grp, "Iotivity starting\n");

    if (!iotivity_task_start()) {
        iot_running = 1;
    } else {
        QCLI_Printf(qcli_iot_grp, "Iotivity thread creation failed\n");
    }

    return QCLI_STATUS_SUCCESS_E;
}

static int
iot_stat_cb(struct stats_hdr *shdr, void *arg, char *name, uint16_t off)
{
    void *stat_val;

    stat_val = (uint8_t *)shdr + off;
    switch (shdr->s_size) {
    case sizeof (uint16_t):
        QCLI_Printf(qcli_iot_grp, "  %s: %u\n", name, *(uint16_t *) stat_val);
        break;
    case sizeof (uint32_t):
        QCLI_Printf(qcli_iot_grp, "  %s: %lu\n", name,
                    *(unsigned long *) stat_val);
        break;
    case sizeof (uint64_t):
        QCLI_Printf(qcli_iot_grp, "  %s: %llu\n", name, *(uint64_t *) stat_val);
        break;
    default:
        break;
    }
    return 0;
}

static int
iot_stat_group_cb(struct stats_hdr *hdr, void *arg)
{
    QCLI_Printf(qcli_iot_grp, "%s\n", hdr->s_name);
    stats_walk(hdr, iot_stat_cb, NULL);
    return 0;
}

static QCLI_Command_Status_t
iot_stats(uint32_t Parameter_Count, QCLI_Parameter_t *Parameter_List)
{
    QCLI_Printf(qcli_iot_grp, "Iotivity statistics\n");

    stats_group_walk(iot_stat_group_cb, NULL);

    return QCLI_STATUS_SUCCESS_E;
}

#include <qapi_otp_tlv.h>

static QCLI_Command_Status_t
iot_mem(uint32_t Parameter_Count, QCLI_Parameter_t *Parameter_List)
{
    struct os_mempool *prev_mp;
    struct os_mempool_info omi;

    QCLI_Printf(qcli_iot_grp, "Iotivity memory use\n");

    QCLI_Printf(qcli_iot_grp, "%32s %5s %4s %4s %4s\n", "name", "blksz",
                               "cnt", "free", "min");
    prev_mp = NULL;
    while (1) {
        prev_mp = os_mempool_info_get_next(prev_mp, &omi);
        if (!prev_mp) {
            break;
        }
        QCLI_Printf(qcli_iot_grp, "%32s %5d %4d %4d %4d\n", omi.omi_name,
                       omi.omi_block_size, omi.omi_num_blocks,
                       omi.omi_num_free, omi.omi_min_free);
    }
    return QCLI_STATUS_SUCCESS_E;
}

