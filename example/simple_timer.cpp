/*
 *定时每秒输出geme over
 */

#include <stdio.h>
#include <iostream>

#include <event.h>
using namespace std;

struct event ev;
struct timeval tv;

//定时事件回调函数
void time_cb(int sock, short event, void *arg) {
	cout << "game over !" << endl;
	event_add(&ev, &tv);
}

int main() {
	//初始化
	struct event_base *base = event_init();

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	//设置定时事件
	//等价于evtimer_set(&ev, time_cb, NULL);
	event_set(&ev, -1, 0, time_cb, NULL);
	
	//添加定时事件
	event_add(&ev, &tv);

	//事件循环
	event_base_dispatch(base);
	
	return 0;
}
