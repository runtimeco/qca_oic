#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <log/log.h>
#include <stats/stats.h>
#include <os/os.h>
#include <mem/mem.h>

#include <qurt_mutex.h>
#include <qurt_timer.h>
#include <qurt_thread.h>

#include "iotivity_priv.h"

#define IOT_THREAD_PRIORITY	24
#define IOT_THREAD_STACK_SIZE	2048

static qurt_timer_t os_tmr;
static struct qurt_timer_attr os_tmr_attr;

static struct qurt_thread_attr iot_thr_attr;
static qurt_thread_t iot_thr_handle;

static STAILQ_HEAD(, stats_hdr) stats_list =
	STAILQ_HEAD_INITIALIZER(stats_list);

static char print_buf[LOG_PRINTF_MAX_ENTRY_LEN];

void
log_printf(struct log *log, uint16_t module, uint16_t level, char *msg, ...)
{
    va_list args;
    int len;

    va_start(args, msg);
    len = vsnprintf(print_buf, LOG_PRINTF_MAX_ENTRY_LEN, msg, args);
    if (len >= LOG_PRINTF_MAX_ENTRY_LEN) {
        len = LOG_PRINTF_MAX_ENTRY_LEN - 1;
	print_buf[LOG_PRINTF_MAX_ENTRY_LEN - 1] = '\0';
    }

    iotivity_printf(print_buf);
}

static int loop_cnt = 0;

void
__assert_func(const char *file, int line, const char *func,
    const char *failedExpr)
{
    char buf[LOG_PRINTF_MAX_ENTRY_LEN];

    snprintf(buf, LOG_PRINTF_MAX_ENTRY_LEN, "assert() %s:%d\n", file, line);
    iotivity_printf(buf);
    while(1) {
        loop_cnt++;
    }
}

int
hal_bsp_hw_id(uint8_t *id, int max_len)
{
    int rc;
    const char *addr;
    uint32_t alen;

    memset(id, 0x42, max_len);

    /*
     * XXX use Wi-Fi mac address as part of uuid, if available
     */
    rc = qapi_Net_Interface_Get_Physical_Address("wlan0", &addr, &alen);
    if (rc == 0) {
        if (alen < max_len) {
            max_len = alen;
        }
        memcpy(id, addr, max_len);
    }
    return max_len;
}

/**
 * Walk a specific statistic entry, and call walk_func with arg for
 * each field within that entry.
 *
 * Walk func takes the following parameters:
 *
 * - The header of the statistics section (stats_hdr)
 * - The user supplied argument
 * - The name of the statistic (if STATS_NAME_ENABLE = 0, this is
 *   ("s%d", n), where n is the number of the statistic in the structure.
 * - A pointer to the current entry.
 *
 * @return 0 on success, the return code of the walk_func on abort.
 *
 */
int
stats_walk(struct stats_hdr *hdr, stats_walk_func_t walk_func, void *arg)
{
    char *name;
    char name_buf[12];
    uint16_t cur;
    uint16_t end;
    int ent_n;
    int len;
    int rc;
#if MYNEWT_VAL(STATS_NAMES)
    int i;
#endif

    cur = sizeof(*hdr);
    end = sizeof(*hdr) + (hdr->s_size * hdr->s_cnt);

    while (cur < end) {
        /*
         * Access and display the statistic name.  Pass that to the
         * walk function
         */
        name = NULL;
#if MYNEWT_VAL(STATS_NAMES)
        /* The stats name map contains two elements, an offset into the
         * statistics entry structure, and the name corresponding with that
         * offset.  This annotation allows for naming only certain statistics,
         * and doesn't enforce ordering restrictions on the stats name map.
         */
        for (i = 0; i < hdr->s_map_cnt; ++i) {
            if (hdr->s_map[i].snm_off == cur) {
                name = hdr->s_map[i].snm_name;
                break;
            }
        }
#endif
        /* Do this check irrespective of whether MYNEWT_VALUE(STATS_NAMES)
         * is set.  Users may only partially name elements in the statistics
         * structure.
         */
        if (name == NULL) {
            ent_n = (cur - sizeof(*hdr)) / hdr->s_size;
            len = snprintf(name_buf, sizeof(name_buf), "s%d", ent_n);
            name_buf[len] = '\0';
            name = name_buf;
        }

        rc = walk_func(hdr, arg, name, cur);
        if (rc != 0) {
            goto err;
        }

        /* Statistics are variable sized, move forward either 16, 32 or 64
         * bits in the structure.
         */
        cur += hdr->s_size;
    }

    return (0);
err:
    return (rc);
}

/**
 * Walk the group of registered statistics and call walk_func() for
 * each element in the list.  This function _DOES NOT_ lock the statistics
 * list, and assumes that the list is not being changed by another task.
 * (assumption: all statistics are registered prior to OS start.)
 *
 * @param walk_func The walk function to call, with a statistics header
 *                  and arg.
 * @param arg The argument to call the walk function with.
 *
 * @return 0 on success, non-zero error code on failure
 */
int
stats_group_walk(stats_group_walk_func_t walk_func, void *arg)
{
    struct stats_hdr *hdr;
    int rc;

    STAILQ_FOREACH(hdr, &stats_list, s_next) {
        rc = walk_func(hdr, arg);
        if (rc != 0) {
            goto err;
        }
    }
    return (0);
err:
    return (rc);
}

int
stats_init_and_reg(struct stats_hdr *shdr, uint8_t size, uint8_t cnt,
                   const struct stats_name_map *map, uint8_t map_cnt,
                   char *name)
{
    memset((uint8_t *)shdr + sizeof(*shdr), 0, size * cnt);

    shdr->s_size = size;
    shdr->s_cnt = cnt;
    shdr->s_name = name;

#if MYNEWT_VAL(STATS_NAMES)
    shdr->s_map = map;
    shdr->s_map_cnt = map_cnt;
#endif
    STAILQ_INSERT_TAIL(&stats_list, shdr, s_next);

    return 0;
}

os_time_t
os_time_get(void)
{
    return qurt_timer_get_ticks();
}

static inline
void __enable_irq(void)
{
    asm volatile("cpsie i");
}

static inline
void __disable_irq(void)
{
    asm volatile("cpsid i");
}

static inline
uint32_t __get_PRIMASK(void)
{
    uint32_t pri;

    asm volatile("mrs %0, PRIMASK" : "=r"(pri) : : );
    return pri;
}

os_sr_t
os_arch_save_sr(void)
{
    uint32_t isr_ctx;

    isr_ctx = __get_PRIMASK();
    __disable_irq();
    return (isr_ctx & 1);
}

void
os_arch_restore_sr(os_sr_t isr_ctx)
{
    if (!isr_ctx) {
        __enable_irq();
    }
}

int
os_arch_in_critical(void)
{
    uint32_t isr_ctx;

    isr_ctx = __get_PRIMASK();
    return (isr_ctx & 1);
}

static void
iot_os_tick(void *arg)
{
    os_callout_tick();
}

static void
iot_task(void *arg)
{
    iotivity_register_resources();
    while (1) {
        os_eventq_run(os_eventq_dflt_get());
    }
}

#define MSYS_MEMBLK_CNT  14
#define MSYS_MEMBLK_SIZE 128
#define MSYS_MEMPOOL_SIZE  OS_MEMPOOL_SIZE(MSYS_MEMBLK_CNT, MSYS_MEMBLK_SIZE)
static os_membuf_t msys_data[MSYS_MEMPOOL_SIZE];
static struct os_mbuf_pool msys_mbuf_pool;
static struct os_mempool msys_mempool;

int
iotivity_task_start(void)
{
    int rc;
    qurt_time_t ticks;

    rc = mem_init_mbuf_pool(msys_data, &msys_mempool, &msys_mbuf_pool,
                            MSYS_MEMBLK_CNT, MSYS_MEMBLK_SIZE, "mbuf");
    assert(rc == 0);

    rc = os_msys_register(&msys_mbuf_pool);
    assert(rc == 0);

    os_eventq_init(os_eventq_dflt_get());

    /*
     * OS_TICKS_PER_SEC = 100
     */
    qurt_timer_attr_init(&os_tmr_attr);
    ticks = qurt_timer_convert_time_to_ticks(10, QURT_TIME_MSEC);
    qurt_timer_attr_set_duration(&os_tmr_attr, ticks);
    qurt_timer_attr_set_callback(&os_tmr_attr, iot_os_tick, NULL);
    qurt_timer_attr_set_reload(&os_tmr_attr, ticks);
    qurt_timer_attr_set_option(&os_tmr_attr, QURT_TIMER_PERIODIC);
    qurt_timer_create(&os_tmr, &os_tmr_attr);

    /*
     * Create a thread to process events.
     */
    qurt_thread_attr_init(&iot_thr_attr);
    qurt_thread_attr_set_name(&iot_thr_attr, "Iotivity");
    qurt_thread_attr_set_priority(&iot_thr_attr, IOT_THREAD_PRIORITY);
    qurt_thread_attr_set_stack_size(&iot_thr_attr, IOT_THREAD_STACK_SIZE);
    if (qurt_thread_create(&iot_thr_handle, &iot_thr_attr, iot_task, NULL)) {
        return -1;
    }
    qurt_timer_start(os_tmr);

    return 0;
}
