# libevent 基本原理

## libevent 介绍
* libevent是用于开发可扩展的网络服务的基于事件通知的网络库。
  libevnet API提供了一个机制，在文件描述符上的IO事件，信号事件或者超时事件发生时，
  执行事件的回调函数。

* libevent用于替代事件驱动的网络服务中的事件循环。应用只需要调用event_dispatch()
  方法就可以在不需要改动事件循环的情形下自动的添加、删除事件。

* libevent支持如下IO多路复用机制：/dev/poll, kqueue, select, poll, epoll。同时也支持实时信号。  
  内部的事件机制是对暴露的API的完整实现，libevent的更新升级不需要重新更改整个应用。  
  因此，libevent简化了应用开发，提供了可扩展的事件通知机制。 libevent也可以用于多线程应用。 
  
## libevent 主要模块
* event - 事件
> libevent 支持io 定时 信号事件
* eventHandler - 事件处理程序
* reactor
>使用eventDemultiplexer注册、注销事件  
运行事件循环  
当有事件进入就绪状态时，调用注册的回调函数进行处理
* eventDemultiplexer
>由操作系统提供的io多路分发机制，如select,  poll, epoll
  
## libevent 使用方法

* 使用libevent的程序，需要引入< event.h > 头文件，编译时加上参数-levent。
  在使用前，需要调用 **event_init()** 或 **event_base_new()** 来初始化libevent库。
* 对于你想监控的每个文件描述符，你都需要声明一个event结构体，再调用 **event_set()** 方法来初始化结构体的属性成员。
* 激活事件通知机制，需要调用 **event_add()** 方法把event结构体加入到监控事件列表中。  
event结构体在堆内存中进行分配，只要事件在激活状态，就会一直保存在内存中。
* 最后，调用event_dispatch()方法来进入事件循环。

