#define FORWARDER

#define MSG_DF           0x80
#define MSG_MF           0x40
#define MSG_OFFSET       0x3F

#define PMTU             64
#define TRUE  			 1

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
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

int s;
struct sockaddr_in adr_inet;
u32 mqfrag_hash_rnd;
int mtu = PMTU;
u16 msg_id = 0;
u32 local_ip;
int countdown;
int shuffle;
int drop;

int main(int argc, char **argv){
	int z;
	char *srvr_addr = NULL;
	struct sockaddr_in adr_clnt;
	int len_inet;
	int portnumber;
	u8 buffer[BUFSIZE];

	struct msg_buff *p_mbuf;
	struct list_head *pos;
	u8     *data;
	struct sigaction sigint_action;

 	if(argc < 3){
		fprintf(stderr, "Usage: %s ip portnumber\n", argv[0]);
		exit(1);
	} else {
		srvr_addr=argv[1];
		if((portnumber = atoi(argv[2])) <= 0) {
			fprintf(stderr, "Usage: %s ip portnumber\n", argv[0]);
			exit(1);
		}
	}

	read_conf();

	local_ip = get_localip();

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s == -1)
		bail("socket()", EXIT);

	memset(&adr_inet, 0, sizeof adr_inet);
	adr_inet.sin_family=PF_INET;
	adr_inet.sin_port=htons(portnumber);
	if(!inet_aton(srvr_addr, &adr_inet.sin_addr))
		bail("bad address.", EXIT);

	len_inet=sizeof(adr_inet);
	z = bind(s, (struct sockaddr *)&adr_inet, len_inet);
	if(z == -1)
		bail("bind()", EXIT);


	int err = pthread_create(&tid, NULL, worker_run, NULL);
	if(err != 0)
		bail("can't create worker thread!", EXIT);


	for(;;){
		z = recvfrom(s,
			buffer,
			sizeof buffer,
			0,
			(struct sockaddr *)&adr_clnt,
			&len_inet);

   	   if(z < 0)
		   bail("recvfrom()", !EXIT);


	   if((data = malloc(z)) != NULL)
	   	   memcpy(data, buffer, z);
	   else
		   bail("can't malloc for this udp message!", !EXIT);


	   if((p_mbuf = malloc(sizeof(MBUF))) != NULL){
		   memset(p_mbuf, 0, sizeof(MBUF));
	   	   p_mbuf->data = data;
	       p_mbuf->msg_len = z;

	       memcpy(&p_mbuf->sk_addr, &adr_clnt, sizeof(adr_clnt));

	       pthread_mutex_lock(&mqlock_input);
	       list_add_tail(&p_mbuf->list, &input_msg_queue);
	       pthread_mutex_unlock(&mqlock_input);
		   pthread_cond_signal(&mqlock_input_ready);
       }else {
		   bail("can't malloc MBUF!", !EXIT);
           sleep(10);
       }
	}

out:
	pthread_join(tid, NULL);
	close(s);
	return 0;
}


void *worker_run(void *arg)
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
	pthread_exit((void *)0);
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
		return msg_forward(p_mbuf);

	msg = do_msg_defrag(p_mbuf);
	if(!msg)
		return 0;
	if(msg)
		memcpy(&msg->sk_addr, &p_mbuf->sk_addr, sizeof(struct sockaddr_in));

	p_ah = (struct app_hdr *)(msg->data + HLEN);

	return (parse_app_data(msg, p_ah));
}
/*
 * 根据消息类型设置对应的消息处理程序
 *
 * @p_mbuf, 消息结构指针
 * @p_ah,  应用层数据指针
 */
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
		case LOGIN_MSG:
			appl.handler = app_do_login;
			break;

		case EXIT_MSG:
			appl.handler = app_do_exit;
			break;

		default:
			return UNKNOWN_APP;
	}

	return (appl.handler(p_mbuf, p_ah));
out:
	free_msg_buff(p_mbuf);

	return DEFRAG_FAIL;
}

/*
 * 处理收到的用户登录消息
 *
 * @p_mbuff  重组好的"登录消息"业务数据报结构体
 * @p_ah     这个数据报的app头部结构体
 */
int app_do_login(struct msg_buff * p_mbuf, struct app_hdr *p_ah)
{
	struct list_head *pos;
	struct usermap *p_usrmap, *p_who;
	struct login *p_login;
	u32 ip;
	u32 ip_net;
	u16 port;
	u8 who[NAMESIZE];
	u8 user_list[BUFSIZE];
    u8 *where;
	u8 sndbuf[BUFSIZE];
	int nfrag, len, mlen, msg_len;
	struct msg_hdr *mh;
	int FOUND = 0;

	p_login = (struct login *)p_ah;

	where = &user_list[0];
	memset(user_list, 0, sizeof(user_list));


	memcpy(who, p_login->user, NAMESIZE);
	ip = ntohl(p_mbuf->sk_addr.sin_addr.s_addr);
	port = ntohs(p_mbuf->sk_addr.sin_port);

	p_who = map_username(who, ip, port);

   	list_for_each_after_first(pos, &user_queue) {
   		p_usrmap = list_entry(pos, USERMAP, list);

		memcpy(where, p_usrmap->name, NAMESIZE);
		where += NAMESIZE;
		/* 添加对应的用户IP信息 */
		ip_net = htonl(p_usrmap->ip);
		memcpy(where, &ip_net, IP_SIZE);
		where += IP_SIZE;
	    len = make_fwd_login_msg(sndbuf, who, ip);
		nfrag = append_data(mtu, sndbuf, len);
		msg_fragment(nfrag, local_ip, htonl(p_usrmap->ip));
		send_fragments(&frag_queue, p_usrmap);

		free_msg_queue(&frag_queue, &mqlock_frag);
    }

	memset(sndbuf, 0, BUFSIZE);

	mlen = where - &user_list[0];
    len = make_reply_msg(sndbuf, who, ip, user_list, mlen);
	nfrag = append_data(mtu, sndbuf, len);
	msg_fragment(nfrag, local_ip, htonl(p_who->ip));
	send_fragments(&frag_queue, p_who);

	free_msg_queue(&frag_queue, &mqlock_frag);

#ifdef TEST
	list_for_each(pos, &user_queue) {
      	p_usrmap = list_entry(pos, USERMAP, list);
		printf("name=%s ip=%x port=%d login.\n", p_usrmap->name, p_usrmap->ip, p_usrmap->port);
	}
#endif
	return 0;
}

/*
 * 构造登录应答消息REPLY_MSG
 *
 * @sndbuf, 消息缓存
 * @who, 登录应答消息的目标用户
 * @uip, 目标用户IP
 * @user_list, 已经登录用户名-IP
 * @len,  user_list长度
 *
 * return 消息长度
 */
int make_reply_msg(u8 *sndbuf, u8 *who, u32 uip, u8 *user_list, int len)
{
    struct login_reply *p_rep;
	u32 ip;

	ip = htonl(uip);
	p_rep = (struct login_reply *)sndbuf;

	p_rep->h.type = REPLY_MSG;
    p_rep->h.len = sizeof(struct login_reply) + len;
	memcpy(p_rep->user, who, NAMESIZE);
	p_rep->ip = ip;

	if(len)
		memcpy(p_rep->others, user_list, len);

	return p_rep->h.len;
}

/*
 * 构造登录转发消息FWD_LOGIN_MSG
 *
 * @sndbuf, 消息缓存
 * @who, 正在登录的用户
 * @uip, 正在登录的用户IP
 *
 * return 消息长度
 */
int make_fwd_login_msg(u8 *sndbuf, u8 *who, u32 uip)
{
	struct login_fwd * p_fwd;
	u32 ip;

	ip = htonl(uip);
	p_fwd = (struct login_fwd *)sndbuf;

	p_fwd->h.type = FWD_LOGIN_MSG;
    p_fwd->h.len = sizeof(struct login_fwd);
	memcpy(p_fwd->user, who, NAMESIZE);
	p_fwd->ip = ip;

	return p_fwd->h.len;
}

/*
 * 预分段函数
 *
 * @len, 上层业务逻辑数据长度
 * @mtu, 包含分段重组层得最大传输单元
 * @from, 被分段的数据起始地址
 *
 * return 分段段数
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
				/* 分段入队列frag_queue */
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
 * 为分段添加分段重组层头部
 *
 * @num, 分段个数
 * @dest, 消息接收方IP
 *
 * return 可供使用的下一个消息ID
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
	mh->dest = dest;

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
/*
 * 依次发送所有分段给接收方
 *
 * @queue, 分段队列
 * @dest, 消息接收方
 */
void send_fragments(struct list_head *queue, struct usermap *dest)
{
	struct list_head *pos;
	struct sockaddr_in receiver;
	u8 sndbuf[2 * BUFSIZE];
	struct msg_buff *p_mbuf;
	int len, sk_len;
	u32 ip;
	u16 port;

	ip = dest->ip;
	port = dest->port;

	sk_len = sizeof(receiver);
	memset(&receiver, 0, sk_len);

	receiver.sin_family = PF_INET;
	receiver.sin_addr.s_addr = htonl(ip);
	receiver.sin_port = htons(port);

	list_for_each(pos, queue){
		p_mbuf = list_entry(pos, MBUF, list);
		len = p_mbuf->msg_len + HLEN;
		memcpy(sndbuf, p_mbuf->data, len);
		send_msg(sndbuf, len, &receiver, sk_len);
	}
}

void send_msg(u8 *msg, int len, struct sockaddr_in *dest, int sk_len)
{
	int z;

	z=sendto(s,
			msg,
			len,
			0,
			(struct sockaddr *)dest,
			sk_len);

	if(z<0)
		bail("send_msg()", EXIT);
}

/*
 * 建立用户名-IP-PORT映射表，若该用户名已经存在，则更新该
 * 用户名对应IP和端口；若不存在该用户，则创建一个USERMAP
 * 节点，并将该节点加入到user_hash表
 */
struct usermap *map_username(u8 *name, u32 ip, u16 port)
{
	unsigned int hash;
	struct hlist_node *n;
	struct usermap *p_usrmap;


	hash = BKDRHash(name) & (HQ_HASHSZ - 1);
	hlist_for_each_entry(p_usrmap, n, &user_hash[hash], hlist) {
		if(!strcmp(p_usrmap->name, name)){
			p_usrmap->ip = ip;
			p_usrmap->port = port;
			list_move(&p_usrmap->list, &user_queue);

		    return p_usrmap;
		}
    }
	if((p_usrmap = malloc(sizeof(USERMAP))) != NULL){
		memcpy(p_usrmap->name, name, NAMESIZE);
		p_usrmap->ip = ip;
		p_usrmap->port = port;

	    hlist_add_head(&p_usrmap->hlist, &user_hash[hash]);                /* 加入到user_hash */
		list_add(&p_usrmap->list, &user_queue); 							/* 加入到user_queue */

		return p_usrmap;
	}else
		bail("can't malloc USERMAP!", EXIT);
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

/*
 * 返回重组成功的消息
 *
 * @p_mbuf, 正在被处理的消息分段
 * return 0, 重组成功
 * return 1, 重组失败
 */
struct msg_buff * do_msg_defrag(struct msg_buff *p_mbuf)
{
	struct mfq *p_mfq;
	struct msg_hdr *p_mh;
	struct msg_buff *ret = NULL;
	u32 src_ip;
	u32 dest_ip;
	u8 protocol;
	u16 id;

	p_mh = (struct msg_hdr *)p_mbuf->data;
	if((p_mfq = msg_find(p_mh)) != NULL){
		 msg_frag_queue(p_mfq, p_mbuf);
		 if (p_mfq->last_in == (FIRST_IN|LAST_IN) && p_mfq->meat == p_mfq->len)
			 /* 开始重组 */
			 ret = msg_frag_reasm(p_mfq);
		 if(ret)
		 	free_mfq(p_mfq);

		 return ret;
	}
	return NULL;
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

int ranged_rand(int low, int high)
{
	srand((unsigned)time(NULL));
	return (double)rand() / (unsigned int)(RAND_MAX +1) * (high - low) + low;
}

u32 BKDRHash(u8 *str)
{
	unsigned int seed = 131;
	unsigned int hash = 0;

	while(*str){
		hash = hash * seed + (*str++);
	}

	return (hash & 0x7FFFFFFF);
}

/*
 * 查找是否存在和输入的（@src, @dest, mh）相对应的mfq存在
 *
 * @p_mh, 当前分段的msg_hdr指针
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
 * 将新收到的分段插入到对应的mfq的分段链表的正确位置
 *
 * @p_mbuf, 新收到的消息分段
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
 * 重组分段为原始分段
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
		/* 重组 */
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

	p_mfq->frags = NULL;
	return p_new;
out_oversize:

	return NULL;
}

/*
 * 创建MFQ
 */
struct mfq * msg_frag_create(struct msg_hdr *p_mh)
{
	struct mfq *p_mfq;

	if((p_mfq = malloc(sizeof(MFQ))) != NULL) {

		p_mfq->src = ntohl(p_mh->src);
		p_mfq->dest = ntohl(p_mh->dest);
		p_mfq->id = ntohs(p_mh->id);
		p_mfq->protocol = p_mh->protocol;
		p_mfq->last_in = 0;
		p_mfq->len = 0;
		p_mfq->frags = NULL;
		p_mfq->meat = 0;
		app_timer_register(&(p_mfq->timer), countdown, 0, expired_deal, p_mfq);

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

void free_msg_buff(struct msg_buff *p_buf)
{

	free(p_buf->data);
	free(p_buf);
}
/*
 * 消息转发函数
 *
 * @p_mbuf, 消息
 */
int msg_forward(struct msg_buff *p_mbuf)
{
	int nfrag,app_len;
	u8  *p_ah;
	u32 src_ip;
	u32 dest_ip;
	struct list_head *pos;
	struct msg_hdr *p_mh;
	struct usermap *p_usrmap;

	p_mh = (struct msg_hdr *)p_mbuf->data;
	app_len = p_mbuf->msg_len - HLEN;
	src_ip = ntohl(p_mh->src);
	dest_ip = ntohl(p_mh->dest);
	p_ah = p_mbuf->data + HLEN;

	nfrag = append_data(mtu, p_ah, app_len);


	append_frag_head(nfrag, p_mh);

	list_for_each(pos, &user_queue) {
		p_usrmap = list_entry(pos, USERMAP, list);
		if(p_usrmap->ip != dest_ip){

			continue;
		}else{

			send_fragments(&frag_queue, p_usrmap);
			break;
		}
	}

	free_msg_queue(&frag_queue, &mqlock_frag);
	free(p_mbuf);

	return 0;
}

/*
 * 给转发报文片段加上头部
 *
 * @num, 分段数目
 * @p_mh, 指向当前分段头部的指针
 */
int append_frag_head(int num, struct msg_hdr *p_mh)
{
	struct list_head *pos;
	struct msg_buff *p_mbuf = NULL;
	struct msg_hdr *old_mh;
	struct msg_hdr *mh;
	int prev_frag_len = 0;
	int flags,offset;
	int i = 0;
	int not_last_frag;


	offset = p_mh->frag_off;

	flags = offset & ~MSG_OFFSET;
	offset &= MSG_OFFSET;
	offset <<= 2;

	not_last_frag = flags & MSG_MF;

	list_for_each(pos, &frag_queue){
		p_mbuf = list_entry(pos, MBUF, list);
		memcpy(p_mbuf->data, p_mh, HLEN);

		mh = (struct msg_hdr *)p_mbuf->data;
		prev_frag_len = p_mbuf->msg_len;

		mh->frag_off = offset >> 2;
		offset += prev_frag_len;

		if(not_last_frag || i != num - 1)
			mh->frag_off |= MSG_MF;
		i++;
	}
}

void expired_deal(unsigned int clientreg, void *clientarg)
{
	struct mfq *mfq_del = clientarg;
	write_log(mfq_del);
	free_mfq(mfq_del);
}

int write_log(struct mfq *p_mfq)
{
	FILE *fp=NULL;
	int i;
	u8 buffer[BUFSIZE];
	u8 username[NAMESIZE];
	char size[4];
	struct msg_buff *frag_tmp;

	pthread_mutex_lock(&wrtloglock);

	if((fp = fopen("drop_mfq.log","w+")) == NULL){
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
			ptr = strtok(buffer,"=");
			ptr = strtok(NULL,"=");
			drop = atoi(ptr);

			if(drop == 0)
				printf("drop frags function is disabled!\n");
			else
				printf("drop frags function is enabled!\n");
		}
		else if(drop && strstr(buffer,"frags_drop")){
			ptr = strtok(buffer,":");
			ptr = strtok(NULL, ":");
			memset(frags_num,0,BUFSIZE);
			strcpy(frags_num,ptr);

			ptr = strtok(frags_num,"-");
			if((fragdrop = malloc(sizeof(struct frags_drop))) != NULL){
				fragdrop->num = atoi(ptr);
				printf("the blocks which will drop frag：%d  ",fragdrop->num);
				list_add(&fragdrop->list,&drop_queue);
			}

			while((ptr = strtok(NULL,"-")) != NULL){
				if((fragdrop = malloc(sizeof(struct frags_drop))) != NULL){
					fragdrop->num = atoi(ptr);
					printf("%d  ",fragdrop->num);
					list_add(&fragdrop->list,&drop_queue);
				}
			}
			printf("\n");
		}
		else if(strstr(buffer,"countdown")){
			ptr = strtok(buffer,"=");
			ptr = strtok(NULL,"=");
			countdown = atoi(ptr);

			printf("the timer of mfq's countdown number: %ds\n",countdown);
		}
		else if(strstr(buffer,"pmtu")){
			ptr = strtok(buffer,"=");
			ptr = strtok(NULL,"=");
			mtu = atoi(ptr);

			printf("the PMTU : %d\n",mtu);
		}
	}

	return 0;
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

void bail(const char *on_what, int flag){
	fputs(strerror(errno), stderr);
	fputs(": ", stderr);
	fputs(on_what, stderr);
	fputc('\n', stderr);
	if(flag)
		exit(1);
}

int app_do_exit(struct msg_buff * p_mbuf, struct app_hdr *p_ah)
{
	return 0;
}
