/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2010 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _EVENT_INTERNAL_H_
#define _EVENT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "event2/event-config.h"
#include <sys/queue.h>
#include "event2/event_struct.h"
#include "minheap-internal.h"
#include "evsignal-internal.h"
#include "mm-internal.h"
#include "defer-internal.h"

/* map union members back */

/* mutually exclusive */
#define ev_signal_next	_ev.ev_signal.ev_signal_next
#define ev_io_next	_ev.ev_io.ev_io_next
#define ev_io_timeout	_ev.ev_io.ev_timeout

/* used only by signals */
#define ev_ncalls	_ev.ev_signal.ev_ncalls
#define ev_pncalls	_ev.ev_signal.ev_pncalls

/* Possible values for ev_closure in struct event. */
#define EV_CLOSURE_NONE 0
#define EV_CLOSURE_SIGNAL 1
#define EV_CLOSURE_PERSIST 2

//定义了libevent框架的底层实现
//其成员是一系列函数指针
/** Structure to define the backend of a given event_base. */
struct eventop {
	/** The name of this backend. */
	const char *name;
	/** Function to set up an event_base to use this backend.  It should
	 * create a new structure holding whatever information is needed to
	 * run the backend, and return it.  The returned pointer will get
	 * stored by event_init into the event_base.evbase field.  On failure,
	 * this function should return NULL. */
	void *(*init)(struct event_base *);  //初始化事件
	/** Enable reading/writing on a given fd or signal.  'events' will be
	 * the events that we're trying to enable: one or more of EV_READ,
	 * EV_WRITE, EV_SIGNAL, and EV_ET.  'old' will be those events that
	 * were enabled on this fd previously.  'fdinfo' will be a structure
	 * associated with the fd by the evmap; its size is defined by the
	 * fdinfo field below.  It will be set to 0 the first time the fd is
	 * added.  The function should return 0 on success and -1 on error.
	 */
	int (*add)(struct event_base *, evutil_socket_t fd, short old, short events, void *fdinfo); //注册事件
	/** As "add", except 'events' contains the events we mean to disable. */
	int (*del)(struct event_base *, evutil_socket_t fd, short old, short events, void *fdinfo); //删除事件
	/** Function to implement the core of an event loop.  It must see which 
	    added events are ready, and cause event_active to be called for each
	    active event (usually via event_io_active or such).  It should
	    return 0 on success and -1 on error.
	 */
	int (*dispatch)(struct event_base *, struct timeval *);  //事件分发
	/** Function to clean up and free our data from the event_base. */
	void (*dealloc)(struct event_base *);  //注销、释放资源
	/** Flag: set if we need to reinitialize the event base after we fork.
	 */
	int need_reinit;
	/** Bit-array of supported event_method_features that this backend can
	 * provide. */
	enum event_method_feature features;
	/** Length of the extra information we should record for each fd that
	    has one or more active events.  This information is recorded
	    as part of the evmap entry for each fd, and passed as an argument
	    to the add and del functions above.
	 */
	size_t fdinfo_len;
};

#ifdef WIN32
/* If we're on win32, then file descriptors are not nice low densely packed
   integers.  Instead, they are pointer-like windows handles, and we want to
   use a hashtable instead of an array to map fds to events.
*/
#define EVMAP_USE_HT
#endif

/* #define HT_CACHE_HASH_VALS */

//对于windows系统，使用hash表结构的event_io_map
//对于非windows系统，使用数组结构的event_io_map，与event_signal_map结构相同
#ifdef EVMAP_USE_HT
#include "ht-internal.h"
struct event_map_entry;
HT_HEAD(event_io_map, event_map_entry);
#else
#define event_io_map event_signal_map
#endif

/* Used to map signal numbers to a list of events.  If EVMAP_USE_HT is not
   defined, this structure is also used as event_io_map, which maps fds to a
   list of events.
*/
struct event_signal_map {
	/* An array of evmap_io * or of evmap_signal *; empty entries are
	 * set to NULL. */
	//数组，元素为evmap_io * 或 evmap_signal *
	//同一个文件描述符fd或者信号值sig是可以多次调用event_new、event_add函数的
	//这里把同一个fd或sig上注册的事件放在同一个队列evmap_io或evmap_signal中
	//entries[x]保存的是fd为x或者sig为x的事件队列
	void **entries;  
	/* The number of entries available in entries */
	int nentries;  //数组元素个数
};

/* A list of events waiting on a given 'common' timeout value.  Ordinarily,
 * events waiting for a timeout wait on a minheap.  Sometimes, however, a
 * queue can be faster.
 **/
struct common_timeout_list {
	/* List of events currently waiting in the queue. */
	struct event_list events;
	/* 'magic' timeval used to indicate the duration of events in this
	 * queue. */
	struct timeval duration;
	/* Event that triggers whenever one of the events in the queue is
	 * ready to activate */
	struct event timeout_event;
	/* The event_base that this timeout list is part of */
	struct event_base *base;
};

struct event_change;

/* List of 'changes' since the last call to eventop.dispatch.  Only maintained
 * if the backend is using changesets. */
struct event_changelist {
	struct event_change *changes;
	int n_changes;
	int changes_size;
};

#ifndef _EVENT_DISABLE_DEBUG_MODE
/* Global internal flag: set to one if debug mode is on. */
extern int _event_debug_mode_on;
#define EVENT_DEBUG_MODE_IS_ON() (_event_debug_mode_on)
#else
#define EVENT_DEBUG_MODE_IS_ON() (0)
#endif


//libevent的reator框架组件
struct event_base {
	/** Function pointers and other data to describe this event_base's
	 * backend. */
	const struct eventop *evsel;  //指向全局变量static const struct eventop * eventops[]中的一个，对应着底层的io多路复用实现
	/** Pointer to backend-specific data. */
	void *evbase;  //eventop的实例对象

	/** List of changes to tell backend about at next dispatch.  Only used
	 * by the O(1) backends. */
	struct event_changelist changelist;  //用于告知后端下一次执行事件分发时需要注意的事件列表

	/** Function pointers used to describe the backend that this event_base
	 * uses for signals */
	const struct eventop *evsigsel;  //专门用于处理信号事件的eventop
	/** Data to implement the common signal handelr code. */
	struct evsig_info sig;  //存储信号处理的信息

	/** Number of virtual events */
	int virtual_event_count;  //虚拟事件的个数
	/** Number of total events added to this event_base */
	int event_count;  //总事件的个数
	/** Number of total events active in this event_base */
	int event_count_active;  //就绪事件的个数

	/** Set if we should terminate the loop once we're done processing
	 * events. */
	int event_gotterm;  //事件循环退出标记，在处理完事件后退出
	/** Set if we should terminate the loop immediately */
	int event_break;  //事件循环退出标记，立即退出

	/** Set if we're running the event_base_loop function, to prevent
	 * reentrant invocation. */
	int running_loop;  //立即启动一个新的事件循环

	/* Active event management. */
	/** An array of nactivequeues queues for active events (ones that
	 * have triggered, and whose callbacks need to be called).  Low
	 * priority numbers are more important, and stall higher ones.
	 */
	struct event_list *activequeues;  //就绪事件队列数组，数组的每个元素保存着一个特定优先级的就绪队列事件链表
	/** The length of the activequeues array */
	int nactivequeues;    //就绪事件队列长度

	/* common timeout logic */

	/** An array of common_timeout_list* for all of the common timeout
	 * values we know. */
	struct common_timeout_list **common_timeout_queues;  //定时到期事件数组
	/** The number of entries used in common_timeout_queues */
	int n_common_timeouts;
	/** The total size of common_timeout_queues. */
	int n_common_timeouts_allocated;

	/** List of defered_cb that are active.  We run these after the active
	 * events. */
	struct deferred_cb_queue defer_queue;  //要延迟处理的就绪事件队列

	/** Mapping from file descriptors to enabled (added) events */
	struct event_io_map io;   //io事件队列

	/** Mapping from signal numbers to enabled (added) events. */
	struct event_signal_map sigmap;  //信号事件队列

	/** All events that have been enabled (added) in this event_base */
	struct event_list eventqueue;  //链表，保存所有注册的事件

	/** Stored timeval; used to detect when time is running backwards. */
	struct timeval event_tv;    //保存后端dispatch()上次返回的时间

	/** Priority queue of events with timeouts. */
	struct min_heap timeheap;  //保存定时事件的小根堆

	/** Stored timeval: used to avoid calling gettimeofday too often. */
	struct timeval tv_cache;  //时间缓存，防止频繁的进行获取当前时间的系统调用

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	/* threading support */
	/** The thread currently running the event_loop for this base */
	unsigned long th_owner_id;
	/** A lock to prevent conflicting accesses to this event_base */
	void *th_base_lock;
	/** The event whose callback is executing right now */
	struct event *current_event;
	/** A condition that gets signalled when we're done processing an
	 * event with waiters on it. */
	void *current_event_cond;
	/** Number of threads blocking on current_event_cond. */
	int current_event_waiters;
#endif

#ifdef WIN32
	/** IOCP support structure, if IOCP is enabled. */
	struct event_iocp_port *iocp;
#endif

	/** Flags that this base was configured with */
	enum event_base_config_flag flags;

	/* Notify main thread to wake up break, etc. */
	/** True if the base already has a pending notify, and we don't need
	 * to add any more. */
	int is_notify_pending;
	/** A socketpair used by some th_notify functions to wake up the main
	 * thread. */
	evutil_socket_t th_notify_fd[2];
	/** An event used by some th_notify functions to wake up the main
	 * thread. */
	struct event th_notify;
	/** A function used to wake up the main thread from another thread. */
	int (*th_notify_fn)(struct event_base *base);
};

struct event_config_entry {
	TAILQ_ENTRY(event_config_entry) next;

	const char *avoid_method;
};

//event_base的基本配置
/** Internal structure: describes the configuration we want for an event_base
 * that we're about to allocate. */
struct event_config {
	TAILQ_HEAD(event_configq, event_config_entry) entries; //队列，记录拒绝使用的后端IO多路复用函数

	int n_cpus_hint;  //记录CPU的数量
	enum event_method_feature require_features;  //记录所选后端需满足的特征
	enum event_base_config_flag flags; //记录一些特性标签
};

/* Internal use only: Functions that might be missing from <sys/queue.h> */
#if defined(_EVENT_HAVE_SYS_QUEUE_H) && !defined(_EVENT_HAVE_TAILQFOREACH)
#ifndef TAILQ_FIRST
#define	TAILQ_FIRST(head)		((head)->tqh_first)
#endif
#ifndef TAILQ_END
#define	TAILQ_END(head)			NULL
#endif
#ifndef TAILQ_NEXT
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#endif

#define TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST(head);					\
	     (var) != TAILQ_END(head);					\
	     (var) = TAILQ_NEXT(var, field))

#ifndef TAILQ_INSERT_BEFORE
#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} while (0)
#endif
#endif /* TAILQ_FOREACH */

#define N_ACTIVE_CALLBACKS(base)					\
	((base)->event_count_active + (base)->defer_queue.active_count)

int _evsig_set_handler(struct event_base *base, int evsignal,
			  void (*fn)(int));
int _evsig_restore_handler(struct event_base *base, int evsignal);

void event_active_nolock(struct event *ev, int res, short count);

/* FIXME document. */
void event_base_add_virtual(struct event_base *base);
void event_base_del_virtual(struct event_base *base);

#ifdef __cplusplus
}
#endif

#endif /* _EVENT_INTERNAL_H_ */

