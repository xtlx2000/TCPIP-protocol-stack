#include "apptimer.h"

unsigned int regnum = 1;      //counter
LIST_HEAD(timer_list);

/*
 * 更新这个定时器的下一个到期时间如果他是个可重复的定时器
 */
void update_timer(struct app_timer *a)
{

    if(a->t_last.tv_sec == 0 && a->t_last.tv_usec == 0) {
        struct timeval t_now;

        gettimeofday(&t_now, NULL);

        a->t_last.tv_sec = t_now.tv_sec;
        a->t_last.tv_usec = t_now.tv_usec;

        a->t_next.tv_sec = t_now.tv_sec + a->t.tv_sec;
        a->t_next.tv_usec = t_now.tv_usec + a->t.tv_usec;

        while(a->t_next.tv_usec >= 1000000) {
            a->t_next.tv_usec -= 1000000;
            a->t_next.tv_sec += 1;
        }
    }
    else if(a->t_next.tv_sec == 0 && a->t_next.tv_usec == 0) {

        if(a->flags & SA_REPEAT) {

            if(a->t.tv_sec == 0 && a->t.tv_usec == 0) {
                app_timer_unregister(a->clientreg);
                return;
            }

            a->t_next.tv_sec = a->t_last.tv_sec + a->t.tv_sec;
            a->t_next.tv_usec = a->t_last.tv_usec + a->t.tv_usec;

            while(a->t_next.tv_usec >= 1000000) {
                a->t_next.tv_usec -= 1000000;
                a->t_next.tv_sec += 1;
            }
        }
        else {
            app_timer_unregister(a->clientreg);
        }
    }


}

/*
* 注销回调函数从一个定时器注册链表
*/
void app_timer_unregister(unsigned int clientreg)
{

    struct app_timer *sa_ptr;
	struct list_head *pos;

	/* sa_ptr通过遍历链表找到要注销的app_time结构体 */
	list_for_each(pos, &timer_list){
		sa_ptr = list_entry(pos,struct app_timer,list);
		if(sa_ptr->clientreg == clientreg)
			break;
	}


    if(sa_ptr != NULL) {
        printf("注销定时器 %d 号\n", sa_ptr->clientreg);
		list_del(&sa_ptr->list);
		(sa_ptr)->t.tv_sec = 0;
		(sa_ptr)->t.tv_usec = 0;
		(sa_ptr)->t_last.tv_sec = 0;
		(sa_ptr)->t_last.tv_usec = 0;
		(sa_ptr)->t_next.tv_sec = 0;
		(sa_ptr)->t_next.tv_usec = 0;
		(sa_ptr)->flags = 0;
		(sa_ptr)->clientarg = NULL;
		(sa_ptr)->thecallback = NULL;
		(sa_ptr)->clientreg = 0;
    }
    else {
    }
}


struct app_timer *find_next_timer(void)
{
    struct app_timer *a, *lowest = NULL;
	struct list_head *pos;

	list_for_each(pos, &timer_list){
		a = list_entry(pos, struct app_timer, list);
		if(lowest == NULL)
			lowest = a;
		else if(a->t_next.tv_sec == lowest->t_next.tv_sec) {
			if(a->t_next.tv_usec < lowest->t_next.tv_usec) {
				lowest = a;
			}
		}else if(a->t_next.tv_sec < lowest->t_next.tv_sec) {
			lowest = a;
		}
	}

	return lowest;
}



/* 按clientreg找到相应的定时器结构体 */
struct app_timer *sa_find_specific(unsigned int clientreg)
{

    struct app_timer *sa_ptr;
	struct list_head *pos;

	list_for_each(pos,&timer_list){
		sa_ptr = list_entry(pos, struct app_timer, list);
        if(sa_ptr->clientreg == clientreg) {
            return sa_ptr;
        }
    }
    return NULL;
}

void run_timers(void)
{
    int done = 0;
    struct app_timer *a = NULL;
    unsigned int clientreg;
    struct timeval t_now;

    while(!done) {
        if((a = find_next_timer()) == NULL) {
            return;
        }

        gettimeofday(&t_now, NULL);

        if((a->t_next.tv_sec < t_now.tv_sec) ||
           ((a->t_next.tv_sec == t_now.tv_sec) &&
            (a->t_next.tv_usec < t_now.tv_usec))) {

            clientreg = a->clientreg;


            (*(a->thecallback)) (clientreg, a->clientarg);


            if((a = sa_find_specific(clientreg)) != NULL) {
                a->t_last.tv_sec = t_now.tv_sec;
                a->t_last.tv_usec = t_now.tv_usec;
                a->t_next.tv_sec = 0;
                a->t_next.tv_usec = 0;

                update_timer(a);
            }
            else {
            }
        }
        else {
            done = 1;
        }
    }

}

/*
 * 注意 timer_handler函数 是基础，这是其他定时器到期处理函数的来源，
 * 因此在timer_handler中我们首先调用这个到期的定时器的处理函数，然后
 * 选择另一个定时器在timer_list然后设置它的剩余时间，当然这个定时器
 * 将成为下一个到期的。
 */
void timer_handler(int a)
{
	 /* 调用到期的定时器的回调函数*/
    run_timers();
    set_an_timer();
}

/*
 * 获得最近到期定时器剩余时间写入delta
 */
int get_next_timer_delay_time(struct timeval *delta)
{
    struct app_timer *sa_ptr;
    struct timeval t_diff, t_now;

    sa_ptr = find_next_timer();

    if(sa_ptr) {
        gettimeofday(&t_now, 0);

        if((t_now.tv_sec > sa_ptr->t_next.tv_sec) ||
           ((t_now.tv_sec == sa_ptr->t_next.tv_sec) &&
            (t_now.tv_usec > sa_ptr->t_next.tv_usec))) {
            delta->tv_sec = 0;
            delta->tv_usec = 1;

            return sa_ptr->clientreg;
        }
        else {
            t_diff.tv_sec = sa_ptr->t_next.tv_sec - t_now.tv_sec;
            t_diff.tv_usec = sa_ptr->t_next.tv_usec - t_now.tv_usec;

            while(t_diff.tv_usec < 0) {
                t_diff.tv_sec -= 1;
                t_diff.tv_usec += 1000000;
            }

            delta->tv_sec = t_diff.tv_sec;
            delta->tv_usec = t_diff.tv_usec;



            return sa_ptr->clientreg;
        }
    }

    return 0;
}

void set_an_timer(void)
{

    struct timeval delta;
    int next_timer = get_next_timer_delay_time(&delta);

    if(next_timer) {
        struct itimerval it;

        it.it_value.tv_sec = delta.tv_sec;//
        it.it_value.tv_usec = delta.tv_usec;
        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = 0;

        signal(SIGALRM, timer_handler);

		/* kick off the timer */
        setitimer(ITIMER_REAL, &it, NULL);
    }
    else {
        /*printf("no timers found to schedule\n");*/
    }
}


unsigned int
app_timer_register(struct app_timer *sa_ptr,unsigned int when, unsigned int flags,
                    APPTimerCallback * thecallback, void *clientarg)
{
	struct list_head *pos;

	list_add_tail(&sa_ptr->list, &timer_list);

    if(sa_ptr == NULL)
        return 0;

    if(0 == when) {
        (sa_ptr)->t.tv_sec = 0;
        (sa_ptr)->t.tv_usec = 1;
    }
    else {
        (sa_ptr)->t.tv_sec = when;
        (sa_ptr)->t.tv_usec = 0;
    }

	(sa_ptr)->t_last.tv_sec = 0;
	(sa_ptr)->t_last.tv_usec = 0;
	(sa_ptr)->t_next.tv_sec = 0;
	(sa_ptr)->t_next.tv_usec = 0;

    (sa_ptr)->flags = flags;
    (sa_ptr)->clientarg = clientarg;
    (sa_ptr)->thecallback = thecallback;
    (sa_ptr)->clientreg = regnum++;

    update_timer(sa_ptr);

    set_an_timer();

    return (sa_ptr)->clientreg;
}
