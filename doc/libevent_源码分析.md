# libevent 源码分析

## 源码结构

1. event.h - libevent网络库的头文件。包含了libevent的概要说明。
    event2/event-structrue.h - libevent主要结构体event的声明
    event2/event.h - libevent提供的接口声明
    event-internal.h 事件处理框架event_base结构体的声明
2. event.c - libevent整体框架的代码实现
3. 系统IO多路复用机制的封装：epoll.c select.c devpoll.c kqueue.c
4. 信号管理： signal.c
5. 缓冲区管理： evbuffer.c buffer.c
6. 辅助函数： evutil.h evutil.c
7. 日志： log.h log.c
8. 基本数据结构： min-heap.h queue.h  libevent_time.h
9. libevent提供的基础应用： dns.h http.h evrpc.h

## 数据结构
#### event结构体

```
struct event {
	TAILQ_ENTRY(event) ev_active_next;  //就绪事件链表节点
	TAILQ_ENTRY(event) ev_next;  //已注册的事件链表节点
	union {
		TAILQ_ENTRY(event) ev_next_with_common_timeout;
		int min_heap_idx;  
	} ev_timeout_pos;  //管理定时事件 (小根堆索引和链表节点)
	evutil_socket_t ev_fd;  //事件源，文件描述符

	struct event_base *ev_base;   //事件处理框架

	union {
		struct {
			TAILQ_ENTRY(event) ev_io_next;
			struct timeval ev_timeout;
		} ev_io;   //管理io事件 (io事件链表节点)

		struct {
			TAILQ_ENTRY(event) ev_signal_next;
			short ev_ncalls;
			short *ev_pncalls;
		} ev_signal;  //管理信号事件 (signal事件链表节点)
	} _ev;

	short ev_events;   //event事件类型，包括：EV_WRITE、EV_READ、EV_TIMEOUT、EV_SIGNAL
	//ev_res和ev_flags是事件激活后回调的结果
	short ev_res;	 //记录了当前激活事件的类型,是读事件还是写事件等
	//用于记录事件的状态，包括：
	//#define EVLIST_TIMEOUT    0x01 
	//#define EVLIST_INSERTED   0x02  事件已经插入到事件列表中。
	//#define EVLIST_SIGNAL        0x04
	//#define EVLIST_ACTIVE        0x08   事件处于激活状态
	//#define EVLIST_INTERNAL  0x10  
	//#define EVLIST_INIT      0x80  事件已经初始化
	short ev_flags;   
	ev_uint8_t ev_pri;	  //记录事件的优先级，数字越小，优先级越高
	//记录事件的终止方式，根据ev_closure的值，当事件发生时，按相应策略执行回调函数
	//#define EV_CLOSURE_NONE 0  （对应除了下面两个之外的其他事件类型）
    //#define EV_CLOSURE_SIGNAL 1  （对应的事件类型：EV_SIGNAL）
	//#define EV_CLOSURE_PERSIST 2 (对应的事件类型：EV_PERSIST)
	ev_uint8_t ev_closure;
	struct timeval ev_timeout;  //timeout事件的超时值

	void (*ev_callback)(evutil_socket_t, short, void *arg);  //回调函数
	void *ev_arg;     //回调函数的参数
};
```

#### event_base 结构体

``` 
struct event_base {
	const struct eventop *evsel;  //指向全局变量static const struct eventop * eventops[]中的一个，对应着底层的io多路复用实现
	void *evbase;  //eventop的实例对象

	struct event_changelist changelist;  //用于告知后端下一次执行事件分发时需要注意的事件列表

	const struct eventop *evsigsel;  //专门用于处理信号事件的eventop
	struct evsig_info sig;  //存储信号处理的信息

	int virtual_event_count;  //虚拟事件的个数
	int event_count;  //总事件的个数
	int event_count_active;  //就绪事件的个数

	int event_gotterm;  //事件循环退出标记，在处理完事件后退出
	int event_break;  //事件循环退出标记，立即退出

	int running_loop;  //立即启动一个新的事件循环

	struct event_list *activequeues;  //就绪事件队列数组，数组的每个元素保存着一个特定优先级的就绪队列事件链表
	int nactivequeues;    //就绪事件队列长度

	struct common_timeout_list **common_timeout_queues;  //定时到期事件数组
	int n_common_timeouts;
	int n_common_timeouts_allocated;

	struct deferred_cb_queue defer_queue;  //要延迟处理的就绪事件队列

	struct event_io_map io;   //io事件队列
	struct event_signal_map sigmap;  //信号事件队列
	struct event_list eventqueue;  //已注册事件队列

	struct timeval event_tv;    //保存后端dispatch()上次返回的时间
	struct min_heap timeheap;  //保存定时事件的小根堆
	struct timeval tv_cache;  //时间缓存，防止频繁的进行获取当前时间的系统调用

#ifndef _EVENT_DISABLE_THREAD_SUPPORT //多线程支持
	unsigned long th_owner_id;
	void *th_base_lock;
	struct event *current_event;
	void *current_event_cond;
	int current_event_waiters;
#endif

#ifdef WIN32
	struct event_iocp_port *iocp;
#endif

	enum event_base_config_flag flags;

	int is_notify_pending;
	evutil_socket_t th_notify_fd[2];
	struct event th_notify;
	int (*th_notify_fn)(struct event_base *base);
};
```

这里要重点关注几个队列：

##### struct event_list eventqueue 已注册事件队列  
event_list是一个双向链表，这个队列保存所有的已注册事件，用于dump所有的event，以及退出libevent时清理所有的event。

定义见（event_struct.h & queue.h）

```
TAILQ_HEAD (event_list, event);
```

```
//TAILQ_HEAD: 队列头
#define TAILQ_HEAD(name, type)  \
struct name {					\
	struct type *tqh_first;		\
	struct type **tqh_last;	    \
}  //tqh_first: 指向队列头元素的指针;tqh_last:二级指针，指向队列最后一个元素的next指针的指针

//TAILQ_ENTRY: 队列元素
#define TAILQ_ENTRY(type)    \
struct {					    \
	struct type *tqe_next;		\ 	
	struct type **tqe_prev;	    \  
}  //tqe_next:指向队列下一个元素的指针; tqe_prev:二级指针，指向队列中上一个元素的next指针的指针
```
##### struct event_io_map io -- io事件的队列  
对于windows系统，使用hash表结构的event_io_map
对于非windows系统，使用数组结构的event_io_map，与event_signal_map结构相同(具体定义见event-internal.h)  

```
#ifdef EVMAP_USE_HT
#include "ht-internal.h"
struct event_map_entry;
HT_HEAD(event_io_map, event_map_entry);
#else
#define event_io_map event_signal_map
#endif
```

下面关注一下windows下使用hash表结构的定义(见evmap.c & ht－internal.h)

```
struct evmap_io {
	struct event_list events;
	ev_uint16_t nread;   //读事件的数目
	ev_uint16_t nwrite;  //写事件的数目
};

#ifdef EVMAP_USE_HT
struct event_map_entry {
	HT_ENTRY(event_map_entry) map_node;
	evutil_socket_t fd;
	union { 
		struct evmap_io evmap_io;
	} ent;
};

```

```
#define HT_HEAD(name, type)        \
  struct name {                    \
    struct type **hth_table;       \
    unsigned hth_table_length;     \
    unsigned hth_n_entries;        \
    unsigned hth_load_limit;       \
    int hth_prime_idx;             \
  }
```

整理来看：event_io_map 是一个hash表，里面的元素是event_map_entry，event_map_entry又包含了fd和evmap_io，evmap_io里面包含了属于该fd的io事件队列

##### struct event_signal_map sigmap -- 信号事件的队列  

event_signal_map和event_io_map的区别在于event_signal_map 是一个数组，而event_io_map是一个hash表。
event_signal_map的数据结构要简单很多，定义见 event-internal.c & evmap.c。

```
struct event_signal_map {
	void **entries;  
	int nentries;  //数组元素个数
};
```
```
struct evmap_signal {
	struct event_list events;
};
```

event_signal_map的数组元素为evmap_io * 或 evmap_signal *  
entries[x]保存的是fd为x或者sig为x的事件队列  
同一个文件描述符fd或者信号值sig是可以多次调用event_new、event_add函数的，这里把同一个fd或sig上注册的事件放在同一个队列evmap_io或evmap_signal中

##### struct event_list *activequeues  -- 就绪事件队列数组

activequeues 是一个数组，元素就是事件队列，这里根据事件优先级的不同，放入起优先级所对应的事件队列中。

## 核心API

#### event_init

event_init()方法负责初始化libevent。  

```
struct event_base *
event_init(void)
{
	struct event_base *base = event_base_new_with_config(NULL);

	if (base == NULL) {
		event_errx(1, "%s: Unable to construct event_base", __func__);
		return NULL;
	}

	current_base = base;

	return (base);
}
```

event_base_new_with_config() 负责俄创建event_base.
首先从对内存中申请空间创建event_base，然后初始化event_base的各成员变量。

```
struct event_base *
event_base_new_with_config(const struct event_config *cfg)
{
	int i;
	struct event_base *base;
	int should_check_environment;
	...

	//为event_base实例申请空间
	if ((base = mm_calloc(1, sizeof(struct event_base))) == NULL) {
		event_warn("%s: calloc", __func__);
		return NULL;
	}
	detect_monotonic();
	gettime(base, &base->event_tv);

	min_heap_ctor(&base->timeheap);  //初始化管理定时事件的minheap
	TAILQ_INIT(&base->eventqueue);   //初始化已注册事件队列
	base->sig.ev_signal_pair[0] = -1;
	base->sig.ev_signal_pair[1] = -1;
	base->th_notify_fd[0] = -1;
	base->th_notify_fd[1] = -1;

	event_deferred_cb_queue_init(&base->defer_queue);
	base->defer_queue.notify_fn = notify_base_cbq_callback;
	base->defer_queue.notify_arg = base;
	if (cfg)
		base->flags = cfg->flags;
    
	evmap_io_initmap(&base->io); 	//初始化event_io_map
	evmap_signal_initmap(&base->sigmap); 	//初始化event_signal_map
	event_changelist_init(&base->changelist);

	base->evbase = NULL;

	should_check_environment =
	    !(cfg && (cfg->flags & EVENT_BASE_FLAG_IGNORE_ENV));
	
	//配置libevent的后端
	for (i = 0; eventops[i] && !base->evbase; i++) {
		if (cfg != NULL) {
			if (event_config_is_avoided_method(cfg,
				eventops[i]->name))  //略过event_config中配置的禁止使用的后端io
				continue;
			if ((eventops[i]->features & cfg->require_features)
			    != cfg->require_features)
				continue;
		}

		//略过当前环境不可用的后端io
		if (should_check_environment &&
		    event_is_method_disabled(eventops[i]->name))
			continue;

		base->evsel = eventops[i];
		//初始化具体的后端io多路复用对象，参见具体的后端io多路复用的实现
		base->evbase = base->evsel->init(base);
	}

	if (base->evbase == NULL) {  //找不到可用的后端io服务
		...
		return NULL;
	}

	//初始化一个优先级队列，存放就绪事件
	if (event_base_priority_init(base, 1) < 0) {
		event_base_free(base);
		return NULL;
	}

	//多线程环境准备
#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	if (!cfg || !(cfg->flags & EVENT_BASE_FLAG_NOLOCK)) {
		int r;
		EVTHREAD_ALLOC_LOCK(base->th_base_lock,
		    EVTHREAD_LOCKTYPE_RECURSIVE);
		base->defer_queue.lock = base->th_base_lock;
		EVTHREAD_ALLOC_COND(base->current_event_cond);
		r = evthread_make_base_notifiable(base);
		if (r<0) {
			event_base_free(base);
			return NULL;
		}
	}
#endif

	...

	return (base);
}

```

#### event_set

event_set()方法用于设置事件。  
参数说明：  
**ev**: 事件event；**fd**: 事件源，文件描述符；**events**: 在事件源上所关注的事件类型，如EV_READ, EV_WRITE, EV_SIGNAL；**callbak**: 回调函数, 当fd上的event发生时，调用该函数执行处理；**arg**: 回调函数的参数  

```
void
event_set(struct event *ev, evutil_socket_t fd, short events,
	  void (*callback)(evutil_socket_t, short, void *), void *arg)
{
	int r;
	r = event_assign(ev, current_base, fd, events, callback, arg);
	EVUTIL_ASSERT(r == 0);
}
```

event_assign() 方法负责具体的事件初始化。

```
int
event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd, short events, void (*callback)(evutil_socket_t, short, void *), void *arg)
{
	if (!base)
		base = current_base;

	_event_debug_assert_not_added(ev);  

	ev->ev_base = base;      //设置eventbase
	ev->ev_callback = callback;  //设置回调函数
	ev->ev_arg = arg;     //设置回调函数参数
	ev->ev_fd = fd;     //设置文件描述符
	ev->ev_events = events;  //设置监听的事件类型
	...

    //信号事件不能与读写事件一起监听
	if (events & EV_SIGNAL) {
		if ((events & (EV_READ|EV_WRITE)) != 0) {
			event_warnx("%s: EV_SIGNAL is not compatible with "
			    "EV_READ or EV_WRITE", __func__);
			return -1;
		}
		ev->ev_closure = EV_CLOSURE_SIGNAL;
	} else {
		if (events & EV_PERSIST) {
			evutil_timerclear(&ev->ev_io_timeout);
			ev->ev_closure = EV_CLOSURE_PERSIST;
		} else {
			ev->ev_closure = EV_CLOSURE_NONE;
		}
	}
	min_heap_elem_init(ev);
	if (base != NULL) {
		ev->ev_pri = base->nactivequeues / 2;   //默认设置事件优先级为中间优先级
	}
	_event_debug_note_setup(ev);

	return 0;
}
```

#### event_add

int event_add(struct event *ev, const struct timeval *tv)  
注册事件  
根据事件的类型（IO、信号、定时）将event结构体加入到相应的事件队列中。  
先注册IO或信号事件，成功后再注册定时事件。

```
int
event_add(struct event *ev, const struct timeval *tv)
{
	int res;
	if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return -1;
	}

	//加锁
	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);
	res = event_add_internal(ev, tv, 0);
	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);

	return (res);
}
```

```
static inline int
event_add_internal(struct event *ev, const struct timeval *tv,
    int tv_is_absolute)  //tv_is_absolute 为0时表示tv为当前时间的相对时间，为1时表示tv为绝对时间

{
	struct event_base *base = ev->ev_base;
	int res = 0;
	int notify = 0;

	EVENT_BASE_ASSERT_LOCKED(base);
	_event_debug_assert_is_setup(ev);
	EVUTIL_ASSERT(!(ev->ev_flags & ~EVLIST_ALL));

    //对于新的timer事件，首先在堆上预留一个位置，如果后续事件注册失败，将不会影响堆内部元素状态
	if (tv != NULL && !(ev->ev_flags & EVLIST_TIMEOUT)) {
		if (min_heap_reserve(&base->timeheap,
			1 + min_heap_size(&base->timeheap)) == -1)
			return (-1);  /* ENOMEM == errno */
	}

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	if (base->current_event == ev && (ev->ev_events & EV_SIGNAL)
	    && !EVBASE_IN_THREAD(base)) {
		++base->current_event_waiters;
		EVTHREAD_COND_WAIT(base->current_event_cond, base->th_base_lock);
	}
#endif

    //如果事件不在已注册或者激活队列中，则调用evbase注册事件
	if ((ev->ev_events & (EV_READ|EV_WRITE|EV_SIGNAL)) &&
	    !(ev->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE))) {
		//对于io或信号事件，调用后端io多路复用服务将事件注册到event_base,具体参见evmap.c中的实现
		if (ev->ev_events & (EV_READ|EV_WRITE))
			res = evmap_io_add(base, ev->ev_fd, ev);
		else if (ev->ev_events & EV_SIGNAL)
			res = evmap_signal_add(base, (int)ev->ev_fd, ev);
		if (res != -1)
			//将注册的事件插入到libevent的已注册队列中
			event_queue_insert(base, ev, EVLIST_INSERTED);
		if (res == 1) {
			notify = 1;
			res = 0;
		}
	}

    //添加定时事件
	//注意如果之前的事件添加失败，则不再添加定时事件
	if (res != -1 && tv != NULL) {
		struct timeval now;
		int common_timeout;

		//对于永久事件，系统会自动记录超时时间，并重新添加事件
		if (ev->ev_closure == EV_CLOSURE_PERSIST && !tv_is_absolute)
			ev->ev_io_timeout = *tv;

		//EVLIST_TIMEOUT表明定时事件已经在堆中了，这时要删除堆中已存在的定时事件
		if (ev->ev_flags & EVLIST_TIMEOUT) {
			if (min_heap_elt_is_top(ev))
				notify = 1;
			event_queue_remove(base, ev, EVLIST_TIMEOUT);
		}

		//如果事件已经是就绪状态，则从就绪队列中激活
		if ((ev->ev_flags & EVLIST_ACTIVE) &&
		    (ev->ev_res & EV_TIMEOUT)) {
			if (ev->ev_events & EV_SIGNAL) {
				if (ev->ev_ncalls && ev->ev_pncalls) {
					*ev->ev_pncalls = 0;
				}
			}

			event_queue_remove(base, ev, EVLIST_ACTIVE);
		}

		//获取当前时间
		gettime(base, &now);
		common_timeout = is_common_timeout(tv, base);
		if (tv_is_absolute) {
			ev->ev_timeout = *tv;
		} else if (common_timeout) {
			struct timeval tmp = *tv;
			tmp.tv_usec &= MICROSECONDS_MASK;
			evutil_timeradd(&now, &tmp, &ev->ev_timeout);
			ev->ev_timeout.tv_usec |=
			    (tv->tv_usec & ~MICROSECONDS_MASK);
		} else {
			evutil_timeradd(&now, tv, &ev->ev_timeout);
		}

		//将定时事件插入到定时事件小根堆中
		event_queue_insert(base, ev, EVLIST_TIMEOUT);
		if (common_timeout) {
			struct common_timeout_list *ctl =
			    get_common_timeout_list(base, &ev->ev_timeout);
			if (ev == TAILQ_FIRST(&ctl->events)) {
				common_timeout_schedule(ctl, &now, ev);
			}
		} else {
			if (min_heap_elt_is_top(ev))
				notify = 1;
		}
	}

	if (res != -1 && notify && EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);

	_event_debug_note_add(ev);

	return (res);
}
```

```
int
evmap_io_add(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
	const struct eventop *evsel = base->evsel;
	struct event_io_map *io = &base->io;
	struct evmap_io *ctx = NULL;
	int nread, nwrite, retval = 0;
	short res = 0, old = 0;
	struct event *old_ev;

	EVUTIL_ASSERT(fd == ev->ev_fd);

	if (fd < 0)
		return 0;

#ifndef EVMAP_USE_HT
	if (fd >= io->nentries) {   //如果fd>io->nentries，需要对数组进行扩容
		if (evmap_make_space(io, fd, sizeof(struct evmap_io *)) == -1)
			return (-1);
	}
#endif
	//获取fd所对应的事件队列
	GET_IO_SLOT_AND_CTOR(ctx, io, fd, evmap_io, evmap_io_init,
						 evsel->fdinfo_len);

	nread = ctx->nread;
	nwrite = ctx->nwrite;

	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;
	
	//如果事件包含读事件，则将读事件计数加1
	if (ev->ev_events & EV_READ) {
		if (++nread == 1)
			res |= EV_READ;
	}
	//如果事件包含写事件，则将写事件计数加1
	if (ev->ev_events & EV_WRITE) {
		if (++nwrite == 1)
			res |= EV_WRITE;
	}
	...

	if (res) {
		void *extra = ((char*)ctx) + sizeof(struct evmap_io);
		//调用后端io多路复用服务添加事件
		if (evsel->add(base, ev->ev_fd,
			old, (ev->ev_events & EV_ET) | res, extra) == -1)
			return (-1);
		retval = 1;
	}

	ctx->nread = (ev_uint16_t) nread;
	ctx->nwrite = (ev_uint16_t) nwrite;
	//将事件ev插入到该fd所在的io事件队列ctx->events中
	TAILQ_INSERT_TAIL(&ctx->events, ev, ev_io_next);

	return (retval);
}
```

event_queue_insert() 方法，将事件加入到指定的队列中，队列通过参数queue指定

```
static void
event_queue_insert(struct event_base *base, struct event *ev, int queue)
{
	EVENT_BASE_ASSERT_LOCKED(base);

	if (ev->ev_flags & queue) {  //如果事件已经在相应的队列中，则不再插入
		...
		return;
	}

	if (~ev->ev_flags & EVLIST_INTERNAL)  //非内部事件，事件计数加1
		base->event_count++;
	
	ev->ev_flags |= queue;  //更新事件状态标记ev_flags
	switch (queue) {
	case EVLIST_INSERTED: 		//io或信号事件，加入已注册事件队列
		TAILQ_INSERT_TAIL(&base->eventqueue, ev, ev_next);
		break;
	case EVLIST_ACTIVE:		    //就绪事件，加入激活事件队列
		base->event_count_active++;
		TAILQ_INSERT_TAIL(&base->activequeues[ev->ev_pri],
		    ev,ev_active_next);
		break;
	case EVLIST_TIMEOUT: {    //定时事件，加入堆
		if (is_common_timeout(&ev->ev_timeout, base)) {
			struct common_timeout_list *ctl =
			    get_common_timeout_list(base, &ev->ev_timeout);
			insert_common_timeout_inorder(ctl, ev);
		} else
			min_heap_push(&base->timeheap, ev);
		break;
	}
	default:
		event_errx(1, "%s: unknown queue %x", __func__, queue);
	}
}

```

#### event_base_loop

int event_base_loop(struct event_base *base, int flags)
事件处理主循环 ：  
更新系统时间  
根据timer_heap中事件的最小超时事件，计算后端io多路服用的最大等待时间   
调用后端io多路服用服务，等待就绪事件的发生，将就绪的io或信号事件插入到激活事件队列中  
将就绪的time_event从小根堆上删除，并加入到激活事件队列中  
调用event_process_active() 处理激活队列中的就绪事件，调用事件回调函数进行处理

```
//事件处理主循环
int
event_base_loop(struct event_base *base, int flags)
{
	const struct eventop *evsel = base->evsel;
	struct timeval tv;
	struct timeval *tv_p;
	int res, done, retval = 0;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	if (base->running_loop) {
		EVBASE_RELEASE_LOCK(base, th_base_lock);
		return -1;
	}
	base->running_loop = 1;

	clear_time_cache(base);  //清空时间缓存

	//设置evsignal_base，指定处理signal所属的event_base实例
	if (base->sig.ev_signal_added && base->sig.ev_n_signals_added)
		evsig_set_base(base);

	done = 0;

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	base->th_owner_id = EVTHREAD_GET_ID();
#endif
	base->event_gotterm = base->event_break = 0;

	//事件主循环
	while (!done) {
		//查看是否需要跳出循环，可以通过调用event_loopexit_cb()设置event_gotterm标记
		if (base->event_gotterm) {
			break;
		}
		//调用event_base_loopbreak()设置event_break标记
		if (base->event_break) {
			break;
		}

		timeout_correct(base, &tv);  //校正系统时间

		//根据timer_heap中事件的最小超时时间，计算后端io多路复用服务的最大等待时间
		tv_p = &tv;
		if (!N_ACTIVE_CALLBACKS(base) && !(flags & EVLOOP_NONBLOCK)) {
			timeout_next(base, &tv_p);
		} else {
			//如果有未处理的就绪事件，让io多路复用立即返回不必等待
			//设置tv_sec=0, tv_usec=0
			evutil_timerclear(&tv);
		}

		//如果没有注册事件，就退出
		if (!event_haveevents(base) && !N_ACTIVE_CALLBACKS(base)) {
			event_debug(("%s: no events registered.", __func__));
			retval = 1;
			goto done;
		}

		gettime(base, &base->event_tv);   //更新last_wait_time
		clear_time_cache(base);		//清空time_cache

		//调用后端io多路复用服务，
		//等待就绪事件的发生，将就绪的io和信号事件插入到激活事件队列中
		res = evsel->dispatch(base, tv_p);

		if (res == -1) {
			retval = -1;
			goto done;
		}

		//将当前系统时间保存到tv_cache中
		update_time_cache(base);

		//检查heap中的timer_events，将就绪的time_event从heap上删除，并插入到激活事件队列中
		timeout_process(base);

		//调用event_process_active()处理激活队列中的就绪事件，
		//调用其回调函数进行处理
		if (N_ACTIVE_CALLBACKS(base)) {
			int n = event_process_active(base);
			if ((flags & EVLOOP_ONCE)
			    && N_ACTIVE_CALLBACKS(base) == 0
			    && n != 0)
				done = 1;
		} else if (flags & EVLOOP_NONBLOCK)
			done = 1;
	}

done:
	clear_time_cache(base);		//循环结束，清空时间缓存
	base->running_loop = 0;

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	return (retval);
}
```

```
//后端epool的事件处理(epoll.c)
static int
epoll_dispatch(struct event_base *base, struct timeval *tv)
{
	struct epollop *epollop = base->evbase;
	struct epoll_event *events = epollop->events;
	int i, res;
	long timeout = -1;

	if (tv != NULL) {
		timeout = evutil_tv_to_msec(tv);
		...
	}

	epoll_apply_changes(base);
	event_changelist_remove_all(&base->changelist, base);

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	//等待IO事件的发生，返回有多少文件描述符可用
	res = epoll_wait(epollop->epfd, events, epollop->nevents, timeout);

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (res == -1) {
		...
	}

	EVUTIL_ASSERT(res <= epollop->nevents);

	for (i = 0; i < res; i++) {
		int what = events[i].events;
		short ev = 0;

		if (what & (EPOLLHUP|EPOLLERR)) {
			ev = EV_READ | EV_WRITE;
		} else {
			if (what & EPOLLIN)
				ev |= EV_READ;
			if (what & EPOLLOUT)
				ev |= EV_WRITE;
		}

		if (!ev)
			continue;

		//激活io事件
		evmap_io_active(base, events[i].data.fd, ev | EV_ET);
	}

	if (res == epollop->nevents && epollop->nevents < MAX_NEVENT) {
		int new_nevents = epollop->nevents * 2;
		struct epoll_event *new_events;

		new_events = mm_realloc(epollop->events,
		    new_nevents * sizeof(struct epoll_event));
		if (new_events) {
			epollop->events = new_events;
			epollop->nevents = new_nevents;
		}
	}

	return (0);
}
```

```
//激活io事件 (evmap.c)
void
evmap_io_active(struct event_base *base, evutil_socket_t fd, short events)
{
	struct event_io_map *io = &base->io;
	struct evmap_io *ctx;
	struct event *ev;

#ifndef EVMAP_USE_HT
	EVUTIL_ASSERT(fd < io->nentries);
#endif
	GET_IO_SLOT(ctx, io, fd, evmap_io);   //获取该fd所对应的io事件队列

	EVUTIL_ASSERT(ctx);
	//遍历队列，将发生的事件插入到激活队列中
	TAILQ_FOREACH(ev, &ctx->events, ev_io_next) {
		if (ev->ev_events & events)
			event_active_nolock(ev, ev->ev_events & events, 1);
	}
}
```

```
//处理激活队列中的事件 (event.c)
static int
event_process_active(struct event_base *base)
{
	struct event_list *activeq = NULL;
	int i, c = 0;

	//从高优先级到低优先级遍历激活队列数组
	for (i = 0; i < base->nactivequeues; ++i) {
		//遍历某一优先级的激活队列
		if (TAILQ_FIRST(&base->activequeues[i]) != NULL) {
			activeq = &base->activequeues[i];
			c = event_process_active_single_queue(base, activeq);
			if (c < 0)
				return -1;
			else if (c > 0)
				break; 
		}
	}

	event_process_deferred_callbacks(&base->defer_queue,&base->event_break);
	return c;
}
```

```
//遍历某一优先级的激活队列，执行相应的回调函数 (event.c)
static int
event_process_active_single_queue(struct event_base *base,
    struct event_list *activeq)
{
	struct event *ev;
	int count = 0;

	EVUTIL_ASSERT(activeq != NULL);

	
	for (ev = TAILQ_FIRST(activeq); ev; ev = TAILQ_FIRST(activeq)) {
		if (ev->ev_events & EV_PERSIST)
			event_queue_remove(base, ev, EVLIST_ACTIVE);
		else
			event_del_internal(ev);
		if (!(ev->ev_flags & EVLIST_INTERNAL))
			++count;

		event_debug((
			 "event_process_active: event: %p, %s%scall %p",
			ev,
			ev->ev_res & EV_READ ? "EV_READ " : " ",
			ev->ev_res & EV_WRITE ? "EV_WRITE " : " ",
			ev->ev_callback));

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
		base->current_event = ev;
		base->current_event_waiters = 0;
#endif

		//根据信号终止方式的不同，采用不同的策略执行事件回调函数
		switch (ev->ev_closure) {
		case EV_CLOSURE_SIGNAL:
			//执行信号事件的回调函数
			event_signal_closure(base, ev);
			break;
		case EV_CLOSURE_PERSIST:
			//执行永久事件的回调函数
			event_persist_closure(base, ev);
			break;
		default:
		case EV_CLOSURE_NONE:
			EVBASE_RELEASE_LOCK(base, th_base_lock);
			//IO事件，直接调用回调函数
			(*ev->ev_callback)(
				(int)ev->ev_fd, ev->ev_res, ev->ev_arg);
			break;
		}

		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
#ifndef _EVENT_DISABLE_THREAD_SUPPORT
		base->current_event = NULL;
		if (base->current_event_waiters) {
			base->current_event_waiters = 0;
			EVTHREAD_COND_BROADCAST(base->current_event_cond);
		}
#endif

		if (base->event_break)
			return -1;
	}
	return count;
}
```

```
/*
   Process up to MAX_DEFERRED of the defered_cb entries in 'queue'.  If
   *breakptr becomes set to 1, stop.  Requires that we start out holding
   the lock on 'queue'; releases the lock around 'queue' for each deferred_cb
   we process.
 */
static int
event_process_deferred_callbacks(struct deferred_cb_queue *queue, int *breakptr)
{
	int count = 0;
	struct deferred_cb *cb;

#define MAX_DEFERRED 16
	while ((cb = TAILQ_FIRST(&queue->deferred_cb_list))) {
		cb->queued = 0;
		TAILQ_REMOVE(&queue->deferred_cb_list, cb, cb_next);
		--queue->active_count;
		UNLOCK_DEFERRED_QUEUE(queue);

		cb->cb(cb, cb->arg);

		LOCK_DEFERRED_QUEUE(queue);
		if (*breakptr)
			return -1;
		if (++count == MAX_DEFERRED)
			break;
	}
#undef MAX_DEFERRED
	return count;
}
```