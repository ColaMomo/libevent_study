#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>

#include <event.h>
using namespace std;

#define PORT 8080
#define BACKLOG 5
#define MEM_SIZE 1024

//事件base
struct event_base *base;

//写事件回调函数
void on_write(int client_fd, short event, void *arg) {
	char *buffer = (char *)arg;
	cout << "Server write: " << buffer;
	send(client_fd, buffer, strlen(buffer), 0);
	free(buffer);
}

//读事件回调函数
void on_read(int client_fd, short event, void *arg) {
	int size;
	char *buffer = (char *)malloc(MEM_SIZE);
	bzero(buffer, MEM_SIZE);
	size = recv(client_fd, buffer, MEM_SIZE, 0);

	if(size <= 0) {
		cout << "Client close" << endl;

		//连接结束（=0）或连接错误（<0）,将事件删除并释放内存空间
		struct event *read_ev = (struct event*)arg;
		event_del(read_ev);
		delete read_ev;

		close(client_fd);
		return;
	}

	cout << "client send: " << buffer;
	struct event *write_ev = (struct event*)malloc(sizeof(struct event));
	event_set(write_ev, client_fd, EV_WRITE, on_write, buffer);
	event_base_set(base, write_ev);
	event_add(write_ev, NULL);
}

//接收请求事件回调函数
void on_accept(int server_fd, short event, void *arg) {
	int client_fd;
	struct sockaddr_in client_addr;

	socklen_t sin_size = sizeof(client_addr);
	client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &sin_size);

	//连接注册为新事件（EV_PERSIST为事件触发后不默认删除）
	struct event *read_ev = (struct event*)malloc(sizeof(struct event));
	event_set(read_ev, client_fd, EV_READ|EV_PERSIST, on_read, read_ev);
	event_base_set(base, read_ev);
	event_add(read_ev, NULL);
}

int main() {
	int sock;
	struct sockaddr_in server_addr;

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(PORT);

	//创建tcpSocket(sock), 监听8080端口
	sock = socket(AF_INET, SOCK_STREAM, 0);
	bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
	listen(sock, BACKLOG);

	//初始化base
	base = event_base_new();

	struct event listen_ev;
	//设置事件
	event_set(&listen_ev, sock, EV_READ|EV_PERSIST, on_accept, NULL);
	//设置为base事件
	event_base_set(base, &listen_ev);
	//添加事件
	event_add(&listen_ev, NULL);
	//事件循环
	event_base_dispatch(base);

	return 0;
}
