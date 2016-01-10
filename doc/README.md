# lievent

## 安装

* 安装
>tar zxvf libevent-2.0.X.tar.gz  
cd libevent-2.0.X  
./configure –prefix=/usr  
make  
make install  
* 查看是否安装成功：
>ls -al /usr/lib | grep libevent
* 使用：
>g++ XXX.cpp -o XXX **-levent**

## Demo

* simple_timer
>简单的定时器，定时输出一条语句
* simple_tcp_server
>简单的tcp_server