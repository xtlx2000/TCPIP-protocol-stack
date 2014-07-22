#define HOST

#define TRUE             1
#define MAX_BYTES        (255 - AH_SIZE - HLEN)
#define PMTU             128
#define MSG_DF           0x80
#define MSG_MF           0x40
#define MSG_OFFSET       0x3F

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <sys/time.h>
#include <pthread.h>

#include "msg.h"

struct sockaddr_in forwarder;
struct sockaddr_in adr_host;
int s;
int more = 0;
u16 msg_id = 0;
u8 login_name[NAMESIZE];
u32 mqfrag_hash_rnd;
struct msg_buff *ret = NULL;
int enable_trans = 0;
int mtu = PMTU;
u32 local_ip;
int countdown = 180;
int shuffle = 1;
int drop = 0;

int main(int argc, char **argv){
	char *forwarder_addr = NULL;
	int portnumber, len_inet, err, z;
	u8 recvbuf[BUFSIZE];

	struct msg_buff *p_mbuf;
	struct list_head *pos;
	struct msg_hdr *mh;
	u8     *data;
	struct sigaction sigint_action;

 	if(argc < 3){
		fprintf(stderr, "Usage: %s ip portnumber\n", argv[0]);
		exit(1);
	} else {
		forwarder_addr = argv[1];
		if((portnumber = atoi(argv[2])) <= 0) {
			fprintf(stderr, "Usage: %s ip portnumber\n", argv[0]);
			exit(1);
		}

		memcpy(login_name, argv[3], NAMESIZE);
	}

	read_conf();

	local_ip = get_localip();

	memset(&forwarder, 0, sizeof forwarder);
	forwarder.sin_family=PF_INET;
	forwarder.sin_port=htons(portnumber);
	if(!inet_aton(forwarder_addr, &forwarder.sin_addr))
		bail("bad address.", EXIT);

	len_inet = sizeof(forwarder);
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s == -1)
		bail("socket()", EXIT);


	login(login_name);

	err = pthread_create(&login_tid, NULL, frag_run, NULL);

	err = pthread_create(&reasm_tid, NULL, reasm_run, NULL);


	for(; ;){
		z = recvfrom(s, 					/* server socket */
			recvbuf, 						/* receive buffer */
			BUFSIZE,
			0,
			(struct sockaddr *)&forwarder,  /* Forwarder address returned */
			&len_inet);

   	   if(z < 0 )
		   bail("recvfrom()", EXIT);

	   if((data = (u8 *)malloc(z)) != NULL)
	   	   memcpy(data, recvbuf, z);
	   else
		   bail("can't malloc for this udp message!", EXIT);

	   if((p_mbuf = malloc(sizeof(MBUF))) != NULL){
		   memset(p_mbuf, 0, sizeof(MBUF));

	   	   p_mbuf->data = data;
	       p_mbuf->msg_len = z;
		   pthread_mutex_lock(&mqlock_input);
	       list_add_tail(&p_mbuf->list, &input_msg_queue);
	       pthread_mutex_unlock(&mqlock_input);
		   pthread_cond_signal(&mqlock_input_ready);
       }else
		   bail("can't malloc MBUF!", EXIT);
	}

	pthread_join(login_tid, NULL);
	close(s);

	return 0;
}

void *reasm_run(void *arg)
{
	struct list_head *pos;
	struct msg_buff *p_mbuf = NULL;

	mqfrag_hash_rnd = ranged_rand(1, RAND_MAX);

	for(;;) {
		pthread_mutex_lock(&mqlock_input);
		while(list_empty(&input_msg_queue))
			pthread_cond_wait(&mqlock_input_ready, &mqlock_input);

       	pos = (&input_msg_queue)->next;
       	p_mbuf = list_entry(pos, MBUF, list);

		list_del((&input_msg_queue)->next);
		pthread_mutex_unlock(&mqlock_input);

		msg_rcv(p_mbuf);
	}
}

/*
 * 消息处理函数
 */
int msg_rcv(struct msg_buff *p_mbuf)
{
	struct msg_buff *msg = NULL;
	struct msg_hdr *p_mh;
	struct app_hdr *p_ah;
	int    len;

	p_mh = (struct msg_hdr *)p_mbuf->data;

	if(p_mh->ver != 1 || p_mbuf->msg_len <= p_mh->hlen)
		return BAD_MSG;

	if(p_mh->dest != local_ip)
		return DEST_ERR;

	msg = do_msg_defrag(p_mbuf);
	if(!msg)
		return 0;

	p_ah = (struct app_hdr *)(msg->data + HLEN);

	if(p_ah->type & LOGIN_TYPE){
	    pthread_mutex_lock(&login_mqlock);
	    list_add_tail(&msg->list, &login_msg_queue);
	    pthread_mutex_unlock(&login_mqlock);
	    pthread_cond_signal(&login_mqlock_ready);

		return 0;
	}
	return (parse_app_data(msg, p_ah));
}

/*
 * 用户交互线程，处理login_msg_queue队列中的消息
 */
void *frag_run(void *arg)
{
	struct list_head *pos = NULL;
	struct msg_buff *p_mbuf = NULL;
	struct app_hdr *p_ah = NULL;
	int len;

	int cond = 1;
	for(;;){
		pthread_mutex_lock(&login_mqlock);

		while(cond && list_empty(&login_msg_queue))

			pthread_cond_wait(&login_mqlock_ready, &login_mqlock);

		if(!cond && list_empty(&login_msg_queue)){
		    pthread_mutex_unlock(&login_mqlock);

			more = 1;
			goto shortcut;
		}

		cond = 0;
		more = 0;

		if(p_mbuf){
            free_msg_buff(p_mbuf);
		}
        pos = (&login_msg_queue)->next;
        p_mbuf = list_entry(pos, MBUF, list);
		list_del((&login_msg_queue)->next);
		pthread_mutex_unlock(&login_mqlock);

shortcut:

	    p_ah = (struct app_hdr *)(p_mbuf->data + HLEN);
	    parse_app_data(p_mbuf, p_ah);
	}
	pthread_exit((void *)0);
}

int parse_app_data(struct msg_buff *p_mbuf, struct app_hdr *p_ah)
{
	int app_len;

	app_len = p_mbuf->msg_len - HLEN;
	if(p_ah->len != app_len) {
		bail("but app data is corrupted!", !EXIT);
		goto out;
	}

	switch(p_ah->type)
	{
		case FWD_LOGIN_MSG:
			appl.handler = app_do_fwd_login;
			break;

		case REPLY_MSG:
			appl.handler = app_do_reply;
			break;

		case EXIT_MSG:
			appl.handler = app_do_exit;
			break;

		case BEGIN:
			appl.handler = app_do_begin;
			break;

		case END:
			appl.handler = app_do_end;
			break;

		case READY:
			appl.handler = app_do_ready;
			break;

		case DATA:
			appl.handler = app_do_data;
			break;
		default:
			return UNKNOWN_APP;
	}

	return (appl.handler(p_mbuf, p_ah));
out:
	free_msg_buff(p_mbuf);
	return BAD_MSG;
}

int app_do_reply(struct msg_buff *p_mbuf, struct app_hdr *ah)
{
	struct list_head *pos;
	struct usermap *p_usrmap;
	int i, num;
	u8 *where, *ul;
	u16 user_no;
	char who[NAMESIZE], ch, username[NAMESIZE];
	u32 user_ip;
	u32 who_ip;


	num = (ah->len - AH_SIZE) / (NAMESIZE + IP_SIZE) - 1;

	where = ul = (u8 *)ah + AH_SIZE + NAMESIZE + IP_SIZE;

	if(more)
		goto shortcut;

	pthread_mutex_lock(&usrlock);
	for(i = 0; i < num; i++){
	    memcpy(username, where, NAMESIZE);
	    memcpy(&user_ip, where + NAMESIZE, IP_SIZE);

		p_usrmap = map_username(username, ntohl(user_ip));

		where += (NAMESIZE + IP_SIZE);
    }
	pthread_mutex_unlock(&usrlock);

shortcut:

	where = ul;
	printf("[0]MORE ");

    for(i = 0; i < num; i++){
		printf("[%d]%s ", i + 1, where);
		where += NAMESIZE + IP_SIZE;
    }

	where = ul;
	do{

		printf("\nplease choose one user to begin Fragmentation exercise: ");
		scanf("%d", &user_no);


		while((ch = getchar()) != '\n');

		if(user_no == 0){
			goto out;
		}
		if(user_no > 0 && user_no <= num)
			break;
	}while(user_no > num);

	memcpy(who, where + (NAMESIZE + IP_SIZE) * (user_no - 1), NAMESIZE);
	who_ip = ip_find(who);
	send_file(who_ip);

out:
	return 0;
}

/*
 * 向转发服务器发出LOGIN_MSG
 *
 * @name, 登陆者用户名
 */
void login(u8 *name)
{
	int len;
	int nfrag;
	u8 sndbuf[BUFSIZE];
	u32 dest;

	memset(sndbuf, 0, BUFSIZE);


	len = make_login_msg(sndbuf, name);

	nfrag = append_data(mtu, sndbuf, len);

	dest = forwarder.sin_addr.s_addr;

	msg_fragment(nfrag, local_ip, dest);

	send_fragments(&frag_queue);

	free_msg_queue(&frag_queue, &mqlock_frag);
}

/* 构造业务逻辑层登录消息 */
int make_login_msg(u8 *sbuf, u8 *name)
{
	struct login *p_login;

	p_login = (struct login *)sbuf;

	p_login->h.type = LOGIN_MSG;
    p_login->h.len = AH_SIZE + NAMESIZE;
	memcpy(p_login->user, name, NAMESIZE);

	return p_login->h.len;
}

/*
 * 对业务逻辑层消息进行预分段
 *
 * @mtu, 分段重组层允许的最大传输单元
 * @from, 将要被分段的数据起始地址
 * @len, 业务逻辑层消息长度
 *
 * return 分段的段数
 */
int append_data(int mtu, u8 *from, int len)
{
	int n;
	int maxfraglen;
	int fragheaderlen;
	int puredatalen;
	int left;
	int copy;
	struct msg_buff *p_mbuf;

	left = len;
	fragheaderlen = HLEN;

	maxfraglen = ((mtu - fragheaderlen) & ~3) + fragheaderlen;
	puredatalen = maxfraglen - fragheaderlen;

	n = 0;
	while(left > 0){

		n++;
		copy = min(puredatalen, left);

		if((p_mbuf = malloc(sizeof(MBUF))) != NULL){

			if((p_mbuf->data = malloc(copy + fragheaderlen)) != NULL){
				memset(p_mbuf->data, 0, copy + fragheaderlen);

				memcpy(p_mbuf->data + fragheaderlen, from, copy);

				p_mbuf->msg_len = copy;
    		    list_add_tail(&p_mbuf->list, &frag_queue);
			}else
	   			bail("can't malloc for this frag message!", EXIT);
		}else
	   		bail("can't malloc for this p_mbuf structure!", EXIT);
		left -= copy;

		from +=copy;
	}

	return n;
}

/*
 * 为每个分段设置分段重组协议头部
 *
 * @num, 分段个数
 * @src, 发送该分段消息的源主机IP
 * @dest, 接收此分段消息的目的主机IP
 *
 * return 下一个业务逻辑消息所需要的ID
 */
int msg_fragment(int num, u32 src, u32 dest)
{
	struct list_head *pos;
	struct msg_buff *p_mbuf = NULL;
	struct msg_hdr *mh;
	int prev_frag_len;
	int offset = 0;
	int i = 0;


	pos = (&frag_queue)->next;
	p_mbuf = list_entry(pos, MBUF, list);


	mh = (struct msg_hdr *)p_mbuf->data;

	mh->ver = 1;
	mh->hlen = HLEN;
	mh->src = src;
	mh->dest= dest;

	mh->frag_off = MSG_MF;

	mh->protocol = 0x1;
	mh->id = msg_id;
	prev_frag_len = p_mbuf->msg_len;
	i++;

	list_for_each_after_first(pos, &frag_queue){
		p_mbuf = list_entry(pos, MBUF, list);

		mh = (struct msg_hdr *)p_mbuf->data;

		mh->ver = 1;
		mh->hlen = HLEN;

		mh = (struct msg_hdr *)p_mbuf->data;
		mh->src = src;
		mh->dest = dest;
		offset += prev_frag_len;
		mh->frag_off = offset >> 2;

		mh->protocol = 0x01;
		mh->id = msg_id;

		if(i != num - 1 )
			mh->frag_off |= MSG_MF;
		else
			mh->frag_off &= MSG_OFFSET;

		prev_frag_len = p_mbuf->msg_len;
		i++;
	}

	if(i == 1)
		mh->frag_off &= MSG_OFFSET;
	return msg_id++;
}

void send_fragments(struct list_head *queue)
{
	struct list_head *pos;
	u8 sndbuf[2 * BUFSIZE];
	struct msg_buff *p_mbuf;
	int len;

	list_for_each(pos, queue){
		p_mbuf = list_entry(pos, MBUF, list);
		len = p_mbuf->msg_len + HLEN;
		memcpy(sndbuf, p_mbuf->data, len);

		send_msg(sndbuf, len, &forwarder, s);
	}
}

void send_msg(u8 *sbuf, int len, struct sockaddr_in *sk_addr, int sk)
{
	int z;

	z=sendto(sk,
			sbuf,
			len,
			0,
			(struct sockaddr *)sk_addr,
			sizeof(struct sockaddr_in));
	if(z<0)
		bail("sendto()", EXIT);
}

struct msg_buff * do_drop(int *nfrags)
{
	struct list_head *pos;
	struct msg_buff *p_mbuf;
	int drop_seq;
	int n;

	if(*nfrags == 1)
		drop_seq = 1;
	else
  		drop_seq = ranged_rand(1, *nfrags + 1);
    n = 1;
	list_for_each(pos, &frag_queue){

		if(n == drop_seq){
        	p_mbuf = list_entry(pos, MBUF, list);
			list_del(pos);

			(*nfrags)--;
			break;
		}
		n++;
	}

	return p_mbuf;
}
/*
 * 模拟分段的丢失
 *
 * @nfrags, 进行失序模拟的分段数
 */
void do_shuffle(int nfrags)
{
	struct list_head *pos;
	struct msg_buff *p_mbuf = NULL;
	int n;

	for(int i = 0; i < nfrags; i++){

		n = ranged_rand(1, nfrags + 1 - i);

		p_mbuf = getfrag(n);
		if(p_mbuf){

			pthread_mutex_lock(&mqlock_frag);
	    	list_add_tail(&p_mbuf->list, &shuffled_frag_queue);
			pthread_mutex_unlock(&mqlock_frag);
		}
	}
}

/* 根据序号从队列frag_queue中去除元素
 *
 * @num, 应从队列frag_queue中去除的元素序号
 */
struct msg_buff *getfrag(int num)
{
	struct list_head *pos;
	struct msg_buff *p_mbuf = NULL;
	int i;

	i = 1;
	pthread_mutex_lock(&mqlock_frag);
	list_for_each(pos, &frag_queue) {
		if(i == num){
        	p_mbuf = list_entry(pos, MBUF, list);
			list_del(pos);
			break;
		}
		i++;
	}
	pthread_mutex_unlock(&mqlock_frag);
	return p_mbuf;
}

struct usermap *map_username(u8 *name, u32 ip)
{
	unsigned int hash;
	struct hlist_node *n;
	struct usermap *p_usrmap;


	hash = BKDRHash(name) & (HQ_HASHSZ - 1);
	hlist_for_each_entry(p_usrmap, n, &user_hash[hash], hlist) {
		if(!strcmp(p_usrmap->name, name)){

			p_usrmap->ip = ip;

			list_move(&p_usrmap->list, &user_queue);

		    return p_usrmap;
		}
    }

	if((p_usrmap = malloc(sizeof(USERMAP))) != NULL){
		memcpy(p_usrmap->name, name, NAMESIZE);
		p_usrmap->ip = ip;

	    hlist_add_head(&p_usrmap->hlist, &user_hash[hash]);
		list_add(&p_usrmap->list, &user_queue);

		return p_usrmap;
	}else
		bail("can't malloc USERMAP!", EXIT);
}


/* 处理转发服务器转发的登录消息
 *
 * @p_mbuf, 指向分段重组层消息
 * @ah, 指向业务逻辑消息
 */
int app_do_fwd_login(struct msg_buff *p_mbuf, struct app_hdr *p_ah)
{
	struct list_head *pos;
	struct usermap *p_usrmap;
	struct login_fwd *p_fwd;
	char who[NAMESIZE], ch;
	char users[HQ_HASHSZ];
	int  user_no;
	u8 *where;
	u32 user_ip;
	u32 who_ip;

	int FOUND = 0;
	int num = 0;

	memset(users, 0, HQ_HASHSZ);
	where = users;

	p_fwd = (struct login_fwd *)p_ah;
	pthread_mutex_lock(&usrlock);

	if(more)
		goto shortcut;
	memcpy(who, p_fwd->user, NAMESIZE);
	user_ip = p_fwd->ip;

	map_username(who,ntohl(user_ip));
#if debug_mod
	printf_mapuser();
#endif
shortcut:
	printf("[0]MORE ");
	list_for_each(pos, &user_queue) {
      	p_usrmap = list_entry(pos, USERMAP, list);

		memcpy(where, p_usrmap->name, NAMESIZE);
		where += NAMESIZE;
		printf("[%d]%s ", ++num, p_usrmap->name);
	}
	pthread_mutex_unlock(&usrlock);
	if(num){
		do{
			printf("\nChoose one user to begin Fragmentation exercise: ");
			scanf("%d", &user_no);
		    while((ch = getchar()) != '\n');

			if(user_no == 0){
				goto out;
			}
			if(user_no > 0 && user_no <= num)
				break;
		}while(user_no > num);

		memcpy(who, users + NAMESIZE*(user_no - 1), NAMESIZE);
		who_ip = ip_find(who);
		send_file(who_ip);
    }

out:
	return 0;
}

/*
 * 重组消息分段，并返回重组成功后的原始消息
 *
 * @p_mbuf, 被处理的分段消息
 * return 0, 重组成功
 * return 1, 重组失败
 */
struct msg_buff * do_msg_defrag(struct msg_buff *p_mbuf)
{
	struct mfq *p_mfq;
	struct msg_hdr *p_mh;
	struct msg_buff *ret = NULL;

	p_mh = (struct msg_hdr *)p_mbuf->data;

	if((p_mfq = msg_find(p_mh)) != NULL){

		 msg_frag_queue(p_mfq, p_mbuf);
		 if (p_mfq->last_in == (FIRST_IN|LAST_IN) && p_mfq->meat == p_mfq->len)

			 ret = msg_frag_reasm(p_mfq);
		 if(ret)
		 	free_mfq(p_mfq);

		 return ret;
	}
	return NULL;
}

/*
 * 查找一个消息分段对应的mfq实例是否已经存在
 */
struct mfq * msg_find(struct msg_hdr *p_mh)
{
	unsigned int hash;
	struct hlist_node *n;
	struct mfq *p_mfq;
	u16 id;
	u32 src;
	u32 dest;
	u8 protocol;

	id = ntohs(p_mh->id);
	protocol = p_mh->protocol;
	src = ntohl(p_mh->src);
	dest = ntohl(p_mh->dest);


	hash = mqhashfn(id, src, dest, protocol);
	hlist_for_each_entry(p_mfq, n, &mfq_hash[hash], hlist) {

		if(p_mfq->src == src &&
		   p_mfq->dest == dest &&
		   p_mfq->protocol == protocol &&
		   p_mfq->id == id) {

		   return p_mfq;
		}
	}

	return msg_frag_create(p_mh);
}

/*
 * 创建mfq实例
 */
struct mfq * msg_frag_create(struct msg_hdr *p_mh)
{
	struct mfq *p_mfq;

	if((p_mfq = malloc(sizeof(MFQ))) != NULL){
		p_mfq->src = ntohl(p_mh->src);
		p_mfq->dest = ntohl(p_mh->dest);
		p_mfq->id = ntohs(p_mh->id);
		p_mfq->protocol = p_mh->protocol;
		p_mfq->last_in = 0;
		p_mfq->len = 0;
		p_mfq->frags = NULL;
		p_mfq->meat = 0;
		app_timer_register(&(p_mfq->timer), countdown,
						   0, expired_deal, p_mfq);

	} else {
		bail("mfq malloc failed!\n", !EXIT);
		return NULL;
    }

	return msg_frag_intern(p_mfq);
}

struct mfq * msg_frag_intern(struct mfq *p_mfq)
{
	unsigned int hash;

	hash = mqhashfn(p_mfq->id, p_mfq->src, p_mfq->dest, p_mfq->protocol);
	hlist_add_head(&p_mfq->hlist, &mfq_hash[hash]);
	list_add_tail(&p_mfq->lru_list, &mq_lru_list);

	return p_mfq;
}

/*
 * 将新收到的分段插入到mfq_hash[hash]元素对应的mfq的分段链表中
 * 正确的位置
 */
void msg_frag_queue(struct mfq *p_mfq, struct msg_buff *p_mbuf)
{
	struct msg_buff *prev, *next;
	struct msg_hdr *p_mh;
	int flags, offset;
	int end;

	if (p_mfq->last_in & COMPLETE)
		goto err;

	p_mh = (struct msg_hdr *)p_mbuf->data;
	offset = p_mh->frag_off;

	flags = offset & ~MSG_OFFSET;


	offset &= MSG_OFFSET;
	offset <<= 2;
	end = offset + p_mbuf->msg_len - p_mh->hlen;
	if ((flags & MSG_MF) == 0) {

		if(end < p_mfq->len || ((p_mfq->last_in & LAST_IN ) && end != p_mfq->len))
			goto err;

	    p_mfq->last_in |= LAST_IN;

		p_mfq->len = end;
	}else {

		if (end > p_mfq->len) {
			if (p_mfq->last_in & LAST_IN)
				goto err;

			p_mfq->len = end;
		}
	}

	prev = NULL;
	for (next = p_mfq->frags; next != NULL; next = next->next) {
		if(next->offset >= offset)
			break;
		prev = next;
	}
	if(prev) {

		int i = (prev->offset + (prev->msg_len - p_mh->hlen)) - offset;

		if (i > 0) {

			offset += i;
			if (end <= offset)
				goto err;

			p_mbuf->PREV_OLAP = i;
		}
	}

	while (next && next->offset < end) {

		int i = end - next->offset;

		if (i < (next->msg_len - p_mh->hlen)) {
			next->NEXT_OLAP = i;

			next->offset += i;
			p_mfq->meat -= i;

			break;
		} else {

			struct msg_buff *free_it = next;
			next = next->next;
			if (prev)
				prev->next = next;
			else
				p_mfq->frags = next;

			p_mfq->meat -= MSG_DATA_LEN(free_it) - p_mh->hlen;
			free_msg_buff(free_it);
		}
	}
	p_mbuf->offset = offset;
	p_mbuf->next = next;

	if (prev)
		prev->next = p_mbuf;
	else
		p_mfq->frags = p_mbuf;

	p_mfq->meat += (p_mbuf->msg_len - p_mh->hlen);
	if (offset == 0)
		p_mfq->last_in |= FIRST_IN;

	list_move_tail(&p_mfq->lru_list, &mq_lru_list);

	return;
err:
	free_msg_buff(p_mbuf);
}

/*
 * 根据所有分段重组原消息
 */
struct msg_buff *msg_frag_reasm(struct mfq *p_mfq)
{
	struct msg_hdr mh, *p_mh;
	struct msg_buff *p_mbuf;
	struct msg_buff	*p_new;
	struct msg_buff *head = p_mfq->frags;
	int total_len, len;
	int data_len;
	int where;

	memcpy(&mh, head->data, HLEN);
	p_mh = (struct msg_hdr *)head->data;

	total_len = p_mh->hlen + p_mfq->len;

	len = p_mfq->len;

	if (len > 255)
		goto out_oversize;

	where = p_mh->hlen;
	if((p_new = malloc(sizeof(MBUF))) != NULL) {
		if(!(p_new->data = malloc(total_len)))
			bail("can not malloc for p_new->data in msg_frag_reasm()\n", EXIT);

		for (p_mbuf = head; p_mbuf; p_mbuf = head) {
			p_mh = (struct msg_hdr *)p_mbuf->data;

			data_len = MSG_DATA_LEN(p_mbuf) - p_mh->hlen;

			memcpy(p_new->data + where, (u8 *)p_mh + p_mh->hlen, data_len);

			head = head->next;
			where += data_len;
		}
	} else
		bail("reasm malloc failed!\n", EXIT);


	memcpy(p_new->data, &mh, HLEN);
	p_new->msg_len = total_len;

	p_mh = (struct msg_hdr *)p_new->data;
	p_mh->frag_off = 0;

	return p_new;
out_oversize:
	return NULL;
}


int make_begin_msg(u8 *sbuf, u8 *filename, int slen)
{
	struct begin_trans *p_bt;

	p_bt = (struct begin_trans *)sbuf;
	p_bt->h.type = BEGIN;
    p_bt->h.len = AH_SIZE + NAMESIZE + slen;

	memcpy(p_bt->user, login_name, NAMESIZE);
	memcpy(p_bt->file, filename, slen);

	return p_bt->h.len;
}

/*
 * 当收到READY消息后，调用本函数从而允许本地
 * frag_run线程可以继续执行
 *
 * @p_ah, 业务逻辑层数据起始位置
 * @len, 业务逻辑层数据长度
 *
 */
int app_do_ready(struct msg_buff *p_mbuf, struct app_hdr *p_ah)
{
	struct ready *p_rdy;

	p_rdy = (struct ready *)p_ah;
	if(!strcmp(p_rdy->user, login_name)){
		enable_trans = 1;
		return enable_trans;
	}
	return 0;
}

/*
 * 发送携带文件名的BEGIN消息，等待对方
 * 同意随后将发起的文件传输
 *
 * @dest, 目标用户
 * @filename, 被传输的文件名
 * @slen, 文件名长度
 */
void send_begin(u32 dest, u8 *filename, int slen)
{
	int len;
	int nfrag;
	u8 sndbuf[BUFSIZE];

	memset(sndbuf, 0, BUFSIZE);

	len = make_begin_msg(sndbuf, filename, slen);

	nfrag = append_data(mtu, sndbuf, len);

	msg_fragment(nfrag, local_ip, htonl(dest));
	send_fragments(&frag_queue);
	/* 释放已发送分段 */
	free_msg_queue(&frag_queue, &mqlock_frag);
}

/*
 * 向目标用户发送指定的文件
 */
void send_file(u32 dest)
{
	struct msg_buff *p_mbuf;
	struct list_head *pos;
	struct frags_drop *fragdrop;
	char filename[256];
	int fsize;
	char ch;
	u8 data_block[MAX_BYTES];
	u8 sndbuf[BUFSIZE];
	int block_num;
	int frag_num;
	int out_of_order = 0;
	int frag_droped = 0;
	int wait_num = 0;
	int len;
	int block_len;
	FILE *fp = NULL;
	int z;

	memset(filename, 0, sizeof(filename));
	do{
		printf("Please enter the FILE NAME: ");
		scanf("%s", &filename);
	}while(!(fsize = checkfile(filename)));

	send_begin(dest, filename, strlen(filename));

	while(wait_num <= 10 && !enable_trans){
		wait_num++;
		usleep(100000);                         /* 100 ms */
	}

	if(wait_num > 10){
		printf("Timeout 300ms! we have not received the READY_MSG!\n");
		return;
	}

	do{
		printf("Please enter the PMTU(any non-numeric key will use %d as default): ", mtu);
		scanf("%d", &mtu);

		while((ch = getchar()) != '\n');

		if(mtu > 0 && mtu <= 255)
			break;
    }while(1);

	block_num = fsize % MAX_BYTES ? (fsize / MAX_BYTES + 1) : (fsize / MAX_BYTES);
	if(!fp)
    	fp = fopen(filename, "r");

	for(int i = 1; i <= block_num; i++){
		printf(". ");
		fflush(stdout);

		block_len = MAX_BYTES;

		sleep(1);

	    z = fread(data_block, 1, block_len, fp);

		if(z < block_len)
			block_len = z;

		len = make_datatrans_msg(sndbuf, data_block, block_len);
		frag_num = append_data(mtu, sndbuf, len);

		msg_fragment(frag_num, local_ip, htonl(dest));

		list_for_each(pos, &drop_queue){
			fragdrop = list_entry(pos, struct frags_drop, list);
			if(fragdrop->num == i ){
        		p_mbuf = do_drop(&frag_num);
				break;
		    }
		}
		if(shuffle != 0){
			do_shuffle(frag_num);
			send_fragments(&shuffled_frag_queue);
			free_msg_queue(&shuffled_frag_queue, &mqlock_frag);
		}else{
			send_fragments(&frag_queue);
		}

		free_msg_queue(&frag_queue, &mqlock_frag);
	}
	printf("\nTransfer file finished!\n");

	send_end_msg(dest, filename, strlen(filename));
}

/*
 * 收到对方发来的BEGIN消息，解析此消息
 * 并从中得到将要传输的文件名
 *
 * @ah, BEGIN消息头部指针
 */
int app_do_begin(struct msg_buff *p_mbuf, struct app_hdr *ah)
{
	int len, msg_len, nfrag;
	struct begin_trans *bt;
	u8 file_name[256], user_name[NAMESIZE];
	u8 sndbuf[BUFSIZE];  		/* send buffer */
	u32 dest;

	memset(file_name, 0, sizeof(file_name));
	memset(user_name, 0, NAMESIZE);
	memset(sndbuf, 0, BUFSIZE);

	bt =(struct begin_trans *)ah;


	len = bt->h.len - (AH_SIZE + NAMESIZE);

	memcpy(user_name, bt->user, NAMESIZE);
	memcpy(file_name, bt->file, len );

	if(fn_find(user_name, file_name, len)){
		memset(sndbuf, 0, BUFSIZE);

		msg_len = make_ready_msg(sndbuf, user_name, file_name, len);

		nfrag = append_data(mtu, sndbuf, msg_len);
		dest = ip_find(user_name);

		msg_fragment(nfrag, local_ip, htonl(dest));
		send_fragments(&frag_queue);

		free_msg_queue(&frag_queue, &mqlock_frag);

        free_msg_buff(p_mbuf);

		return 0;
	}
	bail("can't receive this file\n", !EXIT);

	return 1;
}

/*
 * 根据给定的用户名在fn_hash表中查找是否有对应的文件描述符
 * 指针，如未找到则创建并打开。如果已经存在对应文件描述符指针
 * 但尚未打开对应文件，则打开该文件指针对应的文件
 *
 * @uname, 用户名
 * @fname, 文件名
 * @len, 文件名长度
 *
 * return FILE*
 */
struct mfn * fn_find(u8 *uname, u8 *fname, int len)
{
	unsigned int hash;
	struct hlist_node *n;
	struct mfn *p_mfn;
	FILE *fp = NULL;


	hash = BKDRHash(uname) & (HQ_HASHSZ - 1);
	hlist_for_each_entry(p_mfn, n, &fn_hash[hash], hlist) {
		if(!strcmp(p_mfn->user, uname)) {

		   if(!p_mfn->fp) {

			   fp = open_file(fname, len, uname);
		   }

		   return p_mfn;
		}
	}

    fp = open_file(fname, len, uname);
	return mfn_create(uname, fp);
}

struct mfn * mfn_create(u8 *uname, FILE *fp)
{
	struct mfn *p_mfn;

	if((p_mfn = malloc(sizeof(struct mfn))) != NULL){
		memcpy(p_mfn->user, uname, NAMESIZE);
		p_mfn->fp = fp;

	} else {
		bail("mfn malloc failed!\n", !EXIT);
		return NULL;
    }

	return mfn_intern(p_mfn, uname);
}

/* 将传入的mfn结构体加载到fn_hash表中 */
struct mfn * mfn_intern(struct mfn *p_mfn, u8 *uname)
{
	unsigned int hash;

	hash = BKDRHash(uname) & (HQ_HASHSZ - 1);
	hlist_add_head(&p_mfn->hlist, &fn_hash[hash]);

	return p_mfn;
}

FILE *open_file(u8 *filename, int len, u8 *username)
{
	FILE *fp = NULL;
	u8 final_name[256];
	u8 token = '_';

	memset(final_name, 0, sizeof(final_name));

	memcpy(final_name, filename, len);
	memcpy(final_name + len, &token, 1);
	memcpy(final_name + len + 1, username, NAMESIZE);

	if(!fp){
		fp = fopen(final_name, "w+");
	}
	return fp;
}

/*
 * 创建READY消息
 *
 * @sndbuf, 消息发送缓存
 * @user, 文件发送方用户名
 * @file, 被发送的文件名
 * @len, 被发送的文件名长度
 *
 * return READY消息长度
 */
int make_ready_msg(u8 *sndbuf, u8 *user, u8 *file, int len)
{
	struct ready *p_rdy;

	p_rdy = (struct ready *)sndbuf;

	p_rdy->h.type = READY;
	p_rdy->h.len = AH_SIZE + NAMESIZE + len;

	memcpy(p_rdy->user, user, NAMESIZE);
	memcpy(p_rdy->file, file, len);

	return p_rdy->h.len;
}

int app_do_data(struct msg_buff *p_mbuf, struct app_hdr *p_ah)
{
	int z;
	FILE *fp;
	u8 username[NAMESIZE];
	u32 ip;
	int app_data_len;
	struct mfn *p_mfn;
	struct datablock *p_data;

	p_data = (struct datablock *)p_ah;
	memcpy(username, p_data->user, NAMESIZE);
	/* 找到mfn */
	p_mfn = fn_find(username, NULL, -1);
	/* 找到fp */
	fp = p_mfn->fp;
	/* 找到数据长度 */
	app_data_len = p_data->h.len;
	z = fwrite(p_data->data, 1, app_data_len - NAMESIZE - AH_SIZE, fp);

	return 0;
}

int app_do_end(struct msg_buff *p_mbuf, struct app_hdr *p_ah)
{
	FILE *fp;
	int len;
	struct mfn *p_mfn;
	struct hlist_node *n;
	u8 user_name[NAMESIZE],file_name[256];
	struct end_trans *et;

	memset(file_name, 0, sizeof(file_name));
	memset(user_name, 0, NAMESIZE);

	et = (struct end_trans *)p_ah;

	len = et->h.len - (AH_SIZE + NAMESIZE);
	memcpy(user_name, et->user, NAMESIZE);
	memcpy(file_name, et->file, len);

	p_mfn = fn_find(user_name,NULL,-1);

	fp = p_mfn->fp;

	fclose(fp);

	hlist_del(&p_mfn->hlist);

	free(p_mfn);

	return 0;
}

int make_datatrans_msg(u8 *sbuf, u8 *data_block, int len)
{
	struct datablock *p_data;

	memset(sbuf,0,sizeof(sbuf));

	p_data = (struct datablock *)sbuf;
	p_data->h.type = DATA;
	p_data->h.len = AH_SIZE + NAMESIZE + len;


	memcpy(p_data->user, login_name, NAMESIZE);

	if(len)
		memcpy(p_data->data, data_block, len);

	return p_data->h.len;
}

int make_end_msg(u8 *sbuf, u8 *filename, int slen)
{
	struct end_trans *p_et;

	memset(sbuf,0,sizeof(sbuf));

	p_et = (struct end_trans *)sbuf;
	p_et->h.type = END;
	p_et->h.len = AH_SIZE + NAMESIZE + slen;

	memcpy(p_et->user, login_name, NAMESIZE);
	memcpy(p_et->file, filename, slen);

	return p_et->h.len;
}

void send_end_msg(u32 dest, u8 *filename, int slen)
{
	int len;
	int nfrag;
	u8 sndbuf[BUFSIZE];

	memset(sndbuf,0,BUFSIZE);
	len = make_end_msg(sndbuf, filename, slen);
	nfrag = append_data(mtu, sndbuf, len);
	msg_fragment(nfrag, local_ip, htonl(dest));
	send_fragments(&frag_queue);

	free_msg_queue(&frag_queue, &mqlock_frag);
}

/*
 * 通过username获取对应IP，若未找到则返回0
 */
u32 ip_find(u8 *name)
{
	unsigned int hash;
	struct hlist_node *n;
	struct usermap *p_usrmap;

	/
	hash = BKDRHash(name) & (HQ_HASHSZ - 1);
	hlist_for_each_entry(p_usrmap, n, &user_hash[hash], hlist) {

		if(!strcmp(p_usrmap->name, name)){
		    return p_usrmap->ip;
		}
	}

	return 0;
}

void free_usermap_list(struct list_head *q, pthread_mutex_t *lock)
{
	struct usermap *pos;
	struct usermap *prev = NULL;

	pthread_mutex_lock(lock);
	list_for_each_entry(pos, q, list){
		if(prev){
			printf("user %s is going to be freed\n", prev->name);
			free(prev);
		}
		prev = pos;

		list_del(&pos->list);
		hlist_del(&pos->hlist);
    }
	if(prev){
		printf("user %s is going to be freed\n", prev->name);
		free(prev);
	}
}

void free_msg_queue(struct list_head *q, pthread_mutex_t *lock)
{
	struct msg_buff *pos;
    struct msg_buff	*prev = NULL;

	if(lock)
		pthread_mutex_lock(lock);

	list_for_each_entry(pos, q, list){
		if(prev){
			free(prev->data);
			free(prev);
		}
		prev = pos;
		list_del(&pos->list);
	}
	if(prev){
		free(prev);
	}


	pthread_mutex_unlock(lock);
}

/*
 * mfq超时垃圾回收处理函数
 */
void expired_deal(unsigned int clientreg, void *clientarg)
{
	struct mfq *mfq_del = clientarg;

	write_log(mfq_del);
	free_mfq(mfq_del);
}

void free_mfq(struct mfq *p_mfq)
{
	struct msg_buff *fp;

	hlist_del(&p_mfq->hlist);
	list_del(&(p_mfq->timer.list));
	list_del(&p_mfq->lru_list);

	fp = p_mfq->frags;
	while(fp){
		struct msg_buff *xp = fp->next;
		free_msg_buff(fp);
		fp = xp;
	}
	free(p_mfq);
}

void free_msg_buff(struct msg_buff *p_buf)
{
	free(p_buf->data);
	free(p_buf);
}

int checkfile(char *filename)
{
	struct stat sbuf;

	if(stat(filename, &sbuf)){
	    fputs(strerror(errno), stderr);
		printf("\n");
		return 0;
	}

	return sbuf.st_size;
}

/*
 * 返回[low, high) 范围内的一个随机数
 */
int ranged_rand(int low, int high)
{
	srand((unsigned)time(NULL));
	return (double)rand() / (unsigned int)(RAND_MAX +1) * (high - low) + low;
}

u32 mqhashfn(u16 id, u32 saddr, u32 daddr, u8 prot)
{
	return jhash_3words((u32)id << 16 | prot, (u32)saddr, (u32)daddr, mqfrag_hash_rnd) & (HQ_HASHSZ - 1);
}

u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	jhash_mix(a, b, c);

	return c;
}

/*
 * 根据字符串str计算散列值
 */
u32 BKDRHash(u8 *str)
{
	unsigned int seed = 131;
	unsigned int hash = 0;

	while(*str){
		hash = hash * seed + (*str++);
	}
	return (hash & 0x7FFFFFFF);
}

int write_log(struct mfq *p_mfq)
{
	FILE *fp=NULL;
	int i;
	u8 buffer[BUFSIZE];
	u8 username[NAMESIZE];
	u8 size[4];
	struct msg_buff *frag_tmp;

	pthread_mutex_lock(&wrtloglock);
	if((fp = fopen("drop_mfq.log","a+")) == NULL){
		fprintf(stderr,"fopen error:%s\n",strerror(errno));
		return 1;
	}
	memset(buffer,0,BUFSIZE);
	strcat(buffer,"MFQ Info:\n");
	fwrite(buffer,strlen(buffer),1,fp);

	memset(buffer,0,BUFSIZE);
	strcat(buffer,"Source   Addr: ");
	u32 ip = ntohl(p_mfq->src);
	u8 *ip_u8;
	ip_u8 = inet_ntoa(*(struct in_addr *)(&ip));
	strcat(buffer,ip_u8);
	strcat(buffer,"\n");
	fwrite(buffer,strlen(buffer),1,fp);

	memset(buffer,0,BUFSIZE);
	strcat(buffer,"Created  time: ");
	strcat(buffer,ctime(&(p_mfq->timer.t_last.tv_sec)));
	strcat(buffer,"Droped   time: ");
	strcat(buffer,ctime(&(p_mfq->timer.t_next.tv_sec)));
	fwrite(buffer,strlen(buffer),1,fp);

	memset(buffer,0,BUFSIZE);
	strcat(buffer,"Received size: ");
	memset(size,0,4);
	sprintf(size,"%d",p_mfq->meat);
	strcat(buffer,size);
	strcat(buffer,"\n");
	fwrite(buffer,strlen(buffer),1,fp);

	for(frag_tmp = p_mfq->frags,i = 1;
			 frag_tmp != NULL;
			 frag_tmp = frag_tmp->next,i++){

		memset(buffer,0,BUFSIZE);
		memset(size,0,4);
		sprintf(size," %d",i);
		strcat(buffer,size);
		strcat(buffer," msg_len = ");
		memset(size,0,4);
		int msg_len = frag_tmp->msg_len;
		sprintf(size,"%d",msg_len);
		strcat(buffer,size);

		strcat(buffer,"  offset = ");
		memset(size,0,4);
		int offset = frag_tmp->offset;
		sprintf(size,"%d",offset);
		strcat(buffer,size);
		strcat(buffer,"\n");
		fwrite(buffer,strlen(buffer),1,fp);
	}

	memset(buffer,0,BUFSIZE);
	strcat(buffer,"------------------------------------------\n");
	fwrite(buffer,strlen(buffer),1,fp);

	fclose(fp);
	pthread_mutex_unlock(&wrtloglock);
}

int read_conf()
{
	printf("loading the config file...\n");

	int num;
	u8 *ptr = NULL;
	FILE *fp = NULL;
	struct frags_drop *fragdrop;
	u8 buffer[BUFSIZE];
	u8 frags_num[BUFSIZE];

	if((fp = fopen("msg.conf","r"))==NULL){
		fprintf(stderr,"fopen error:%s\n",strerror(errno));
		return 1;
	}

	while((fgets(buffer,BUFSIZE,fp)) != NULL){
		if(strstr(buffer,"do_shuffle") != 0){
			ptr = strtok(buffer,"=");
			ptr = strtok(NULL,"=");
			shuffle = atoi(ptr);

			if(shuffle == 0)
				printf("shuffle function is disabled!\n");
			else
				printf("shuffle function is enabled!\n");
		}
		else if(strstr(buffer,"do_drop")){
			ptr = strtok(buffer, "=");
			ptr = strtok(NULL, "=");
			drop = atoi(ptr);

			if(drop == 0)
				printf("drop frags function is disabled!\n");
			else
				printf("drop frags function is enabled!\n");
		}
		else if(drop && strstr(buffer, "frags_drop")){
			ptr = strtok(buffer, ":");
			ptr = strtok(NULL, ":");
			memset(frags_num, 0, BUFSIZE);
			strcpy(frags_num, ptr);

			ptr = strtok(frags_num, "-");
			if((fragdrop = malloc(sizeof(struct frags_drop))) != NULL){
				fragdrop->num = atoi(ptr);
				printf("the blocks which will drop frag：%d  ", fragdrop->num);
				list_add(&fragdrop->list, &drop_queue);
			}

			while((ptr = strtok(NULL, "-")) != NULL){
				if((fragdrop = malloc(sizeof(struct frags_drop))) != NULL){
					fragdrop->num = atoi(ptr);
					printf("%d  ", fragdrop->num);
					list_add(&fragdrop->list, &drop_queue);
				}
			}
			printf("\n");
		}
		else if(strstr(buffer, "countdown")){
			ptr = strtok(buffer, "=");
			ptr = strtok(NULL, "=");
			countdown = atoi(ptr);

			printf("the timer of mfq's countdown number: %ds\n", countdown);
		}
		else if(strstr(buffer, "pmtu")){
			ptr = strtok(buffer, "=");
			ptr = strtok(NULL, "=");
			mtu = atoi(ptr);

			printf("the PMTU : %d\n", mtu);
		}
	}

	return 0;
}

void bail(const char *on_what, int flag){
	fputs(strerror(errno), stderr);
	fputs(": ", stderr);
	fputs(on_what, stderr);
	fputc('\n', stderr);
	if(flag)
		exit(1);
}

u32 get_localip()
{
	int inet_sock;
	struct ifreq ifr;

	inet_sock = socket (PF_INET, SOCK_DGRAM, 0);
	strcpy (ifr.ifr_name, NIC);

	if(ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0)
		perror("ioctl");

	return (((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr.s_addr);
}

int app_do_exit(struct msg_buff * p_mbuf, struct app_hdr *ah)
{
	return 0;
}


