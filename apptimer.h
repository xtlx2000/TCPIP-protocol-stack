
#ifndef TIMER_H
#define TIMER_H

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "list.h"

#define MALLOC_TIMER_STRUCT(s)   (struct s *) calloc(1, sizeof(struct s))
typedef void (APPTimerCallback) (unsigned int clientreg, void *clientarg);
#define SA_REPEAT 0x01   				//可重复标记

/* 定时器结构体  */
struct app_timer {
	struct timeval t;              		//倒计时数字
	unsigned int flags;  				//定时器的类型
	unsigned int clientreg;   			//计数器的编号
	struct timeval t_last;   			//上一次到期时间
	struct timeval t_next;  			//下一次到期时间
	void *clientarg; 					//回调函数的参数
	APPTimerCallback *thecallback; 		//回调函数
	struct list_head list; 				//链表节点
};

/* 函数声明 */
void app_timer_unregister(unsigned int clientreg);
unsigned int app_timer_register(struct app_timer *sa_ptr,
								unsigned int when,
								unsigned int flags,
								APPTimerCallback * thecallback,
								void *clientarg);
void update_timer(struct app_timer *alrm);
struct app_timer *find_next_timer(void);
void run_timers(void);
void timer_handler(int a);
void set_an_timer(void);
int get_next_timer_delay_time(struct timeval *delta);

#endif
