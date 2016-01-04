/*
 * Copyright 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2010 Niels Provos and Nick Mathewson
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
#ifndef _EVSIGNAL_H_
#define _EVSIGNAL_H_

#ifndef evutil_socket_t
#include "event2/util.h"
#endif
#include <signal.h>

typedef void (*ev_sighandler_t)(int);

//信号事件处理的数据结构
/* Data structure for the default signal-handling implementation in signal.c
 */
struct evsig_info {
	/* Event watching ev_signal_pair[1] */
	struct event ev_signal;  //为socket pair的读socket向event_base中注册读事件所使用的结构体
	/* Socketpair used to send notifications from the signal handler */
	evutil_socket_t ev_signal_pair[2];  //socket pair对，ev_signal_pair[0]是写socket，ev_signal_pair[1]是读socket
	/* True iff we've added the ev_signal event yet. */
	int ev_signal_added;  //记录ev_signal事件是否已注册
	/* Count of the number of signals we're currently watching. */
	int ev_n_signals_added;  //当前所监测的信号数目

	/* Array of previous signal handler objects before Libevent started
	 * messing with them.  Used to restore old signal handlers. */
	//sh_old记录了用户原来的signal回调函数
	//由于libevent会为这个信号设置一个回调函数，
	//因此需要保存用户之前设置的回调函数，
	//当用户不再监听这个信号时，就能够回复用户之前的回调函数
#ifdef _EVENT_HAVE_SIGACTION
	struct sigaction **sh_old;
#else
	ev_sighandler_t **sh_old;

#endif
	/* Size of sh_old. */
	int sh_old_max;  //sh_old数组长度
};
int evsig_init(struct event_base *);
void evsig_dealloc(struct event_base *);

void evsig_set_base(struct event_base *base);

#endif /* _EVSIGNAL_H_ */
