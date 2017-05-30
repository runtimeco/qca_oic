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

#ifndef _OS_H
#define _OS_H

#include <stdlib.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef min
#define min(a, b) ((a)<(b)?(a):(b))
#endif

#ifndef max
#define max(a, b) ((a)>(b)?(a):(b))
#endif

#define os_get_return_addr() (__builtin_return_address(0))

#define OS_ALIGN(__n, __a) (                             \
        (((__n) & ((__a) - 1)) == 0)                   ? \
            (__n)                                      : \
            ((__n) + ((__a) - ((__n) & ((__a) - 1))))    \
        )


#define CTASSERT(x) typedef int __ctasssert ## __LINE__[(x) ? 1 : -1]


/**
 * Whether or not the operating system has been started.  Set to
 * 1 right before first task is run.
 */
extern int g_os_started;

int os_info_init(void);

/**
 * Returns 1 if the OS has been started, 0 if it has not yet been
 * been started.
 */
int os_started(void);

/* OS error enumerations */
enum os_error {
    OS_OK = 0,
    OS_ENOMEM = 1,
    OS_EINVAL = 2,
    OS_INVALID_PARM = 3,
    OS_MEM_NOT_ALIGNED = 4,
    OS_BAD_MUTEX = 5,
    OS_TIMEOUT = 6,
    OS_ERR_IN_ISR = 7,      /* Function cannot be called from ISR */
    OS_ERR_PRIV = 8,        /* Privileged access error */
    OS_NOT_STARTED = 9,     /* OS must be started to call this function, but isn't */
    OS_ENOENT = 10,         /* No such thing */
    OS_EBUSY = 11,          /* Resource busy */
    OS_ERROR = 12,          /* Generic Error */
};

#define OS_WAIT_FOREVER (-1)

typedef enum os_error os_error_t;

#define OS_IDLE_PRIO (0xff)
#define OS_MAIN_TASK_PRIO       MYNEWT_VAL(OS_MAIN_TASK_PRIO)
#define OS_MAIN_STACK_SIZE      MYNEWT_VAL(OS_MAIN_STACK_SIZE)

void os_init(int (*fn)(int argc, char **argv));
void os_start(void);

/* XXX: Not sure if this should go here; I want to differentiate API that
 * should be called by application developers as those that should not. */
void os_init_idle_task(void);

#include "os/endian.h"
#include "os/os_callout.h"
#include "os/os_eventq.h"
#include "os/os_heap.h"
#include "os/os_mbuf.h"
#include "os/os_mempool.h"
//#include "os/os_mutex.h"
//#include "os/os_sanity.h"
//#include "os/os_sched.h"
//#include "os/os_sem.h"
//#include "os/os_task.h"
#include "os/os_time.h"

#include "qurt_mutex.h"
#define OS_ALIGNMENT 1

typedef int os_sr_t;

os_sr_t os_arch_save_sr(void);
void os_arch_restore_sr(os_sr_t);
int os_arch_in_critical(void);

#define OS_ENTER_CRITICAL(__os_sr) (__os_sr = os_arch_save_sr())
/* Exit a critical section, restore processor state and unblock interrupts */
#define OS_EXIT_CRITICAL(__os_sr) (os_arch_restore_sr(__os_sr))
#define OS_ASSERT_CRITICAL() (assert(os_arch_in_critical()))

#ifdef __cplusplus
}
#endif

#endif /* _OS_H */
