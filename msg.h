#include "list.h"
#include "apptimer.h"

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned short u16;

#define NIC 		 "eth1"

#define HQ_HASHSZ    64          /* 最大参与分段重组的主机数 */
#define BUFSIZE     512          /* 默认缓存大小 */

#define NAMESIZE      8          /* 最大用户名长度 */
#define IP_SIZE       4          /* ip地址长度 */
#define IP_STR_SIZE   6

#define BAD_MSG      -1                           
#define UNKNOWN_MSG  -2
#define UNKNOWN_APP  -3
#define DEST_ERR     -4
#define DEFRAG_FAIL  -5

#define LOGIN_MSG     1          /* 登录消息 */
#define FWD_LOGIN_MSG 2          /* 登录转发消息 */
#define REPLY_MSG     4          /* 登录应答消息 */
#define EXIT_MSG      8          /* 退出登录消息 */
#define BEGIN         16         /* 请求文件传输消息 */
#define END           32         /* 文件传输结束消息 */
#define READY         64         /* 允许发送方发送文件 */
#define DATA          128        /* 文件数据消息 */
#define LOGIN_TYPE    (LOGIN_MSG|FWD_LOGIN_MSG|REPLY_MSG|EXIT_MSG)
#define COMPLETE      4
#define FIRST_IN	  2
#define LAST_IN		  1

#define EXIT          1

#define JHASH_GOLDEN_RATIO  0x9e3779b9              
#define jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12); \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5);\
  a -= b; a -= c; a ^= (c>>3); \
  b -= c; b -= a; b ^= (a<<10);\
  c -= a; c -= b; c ^= (b>>15);\
} 

#pragma pack(1)                 /* 开始按字节紧凑如下协议数据 */

struct msg_buff{                /* 消息 */
	u8 *data;                   /* 指向为存储收到的udp数据所分配的内存起始地址 */
	int msg_len;                /* 当前收到的udp消息的长度 */ 
#ifdef FORWARDER
	struct sockaddr_in sk_addr;
#endif
	u16 offset;                 /* 消息分段在原始消息中的绝对偏移值 */
	u16 PREV_OLAP;            	/* 当前分段和前一个分段重叠大小 */
	u16 NEXT_OLAP;             	/* 当前分段和后一个分段重叠大小 */
	struct msg_buff *next;      /* 用于分段重组链表中hlist，链接各个分段 */
	struct list_head list;      /* 用于将此消息加入到消息队列中 */
};

struct msg_hdr{                 /* 消息头部 */
	u8   hlen :6,               /* 消息头部长度 */
         ver  :2;               /* 消息版本 */
	u32 src;                    /* 源用户名 */
	u32 dest;                   /* 目标用户名 */
	u16 id;                     /* 分段id */
	u8 frag_off;                /* 分段标志和分段偏移 */
    u8  protocol;               /* 上层协议 */
};

struct app_hdr{                 /* 应用层消息头部 */
	u8 type;                    /* 应用层消息类型 */
	u8 len;                     /* 应用层消息长度 */
};

struct login{
	struct app_hdr h;
    u8 user[NAMESIZE];
};

struct login_fwd{
	struct app_hdr h;
	u8 user[NAMESIZE];
	u32 ip;
};

struct login_reply{
	struct app_hdr h;
	u8 user[NAMESIZE];
	u32 ip;
	u8 others[0];      /* 若有其他用户登录，则紧跟此结构后是已登录用户及其ip地址 */
};

struct login_exit{
	struct app_hdr h;
	u8 user[NAMESIZE];
};

struct begin_trans{
	struct app_hdr h;
	u8 user[NAMESIZE];
	u8 file[256];
};

struct end_trans{
	struct app_hdr h;
	u8 user[NAMESIZE];
	u8 file[256];
};

struct ready{
	struct app_hdr h;
	u8 user[NAMESIZE];
	u8 file[256];
};

struct datablock{
	struct app_hdr h;
	u8 user[NAMESIZE];
	u8 data[0];
};

#pragma pack()        /* 结束紧凑协议数据 */

#define AH_SIZE sizeof(struct app_hdr)
#define min(a, b) ((a - b) > 0) ? b : a 
#define HLEN sizeof(struct msg_hdr)

/* 在分段消息出现前后重叠情况下，获得消息分段的真实长度 */ 
#define MSG_DATA_LEN(p_mbuf) (p_mbuf->msg_len - p_mbuf->PREV_OLAP - p_mbuf->NEXT_OLAP)

/* 为了快速查找用户名和其对应的ip地址，特意在已经存在一个
 * 用户链表情况下，再建立一个以用户名为关键字的散列表
 */ 
struct usermap {
	struct hlist_node hlist;
	struct list_head list;
	u32 ip;
#ifdef FORWARDER
	u16 port;
#endif
	u8  name[NAMESIZE];
};
typedef struct usermap USERMAP;
typedef struct msg_buff MBUF;

/* 未完成分段消息队列元素.*/
struct mfq {
	struct hlist_node hlist;
	struct list_head lru_list;
	u32    src;
	u32    dest;
	u16    id;
	u8	   protocol;     
	u8	   last_in;
	struct msg_buff	*frags;	 
	int		len;			 
	int		meat;
	struct app_timer timer;
};

typedef struct mfq MFQ;
typedef struct app_hdr * P_AH;

/* 丢弃的片段结构体 */
struct frags_drop{
	struct list_head list;
	int num;
};


int append_data(int, u8 *, int);
int msg_fragment(int, u32, u32);
void free_msg_queue(struct list_head *, pthread_mutex_t *);
void free_usermap_list(struct list_head *, pthread_mutex_t *);               
int msg_rcv(struct msg_buff *);
struct msg_buff * do_msg_defrag(struct msg_buff * );
int parse_app_data(struct msg_buff *, struct app_hdr *);
void send_msg(u8 *, int, struct sockaddr_in *, int);
int ranged_rand(int, int);
u32 BKDRHash(u8 *);
void msg_frag_queue(struct mfq *, struct msg_buff *);
struct mfq * msg_find(struct msg_hdr *);
struct msg_buff *msg_frag_reasm(struct mfq *);
u32 mqhashfn(u16, u32, u32, u8);
struct mfq * msg_frag_create(struct msg_hdr *);
u32 jhash_3words(u32, u32, u32, u32);
struct mfq * msg_frag_intern(struct mfq *);
void free_msg_buff(struct msg_buff *);
u32 get_localip();
void free_mfq(struct mfq *);
void expired_deal(unsigned int clientreg, void *clientarg);
int write_log(struct mfq *);
int read_conf();
void bail(const char *, int);
void sig_action(int);

#ifdef HOST  /* host.c的函数原型 */
int app_do_fwd_login(struct msg_buff *, struct app_hdr *);
int make_login_msg(u8 *, u8 *);
void *frag_run(void *);
void *reasm_run(void *);
void send_file(u32);
int app_do_reply(struct msg_buff *, struct app_hdr *);
int app_do_exit(struct msg_buff *, struct app_hdr *);
struct msg_buff *do_drop(int *);
void do_shuffle(int nfrags);
int checkfile(char *);
void send_fragments(struct list_head *);
struct msg_buff *getfrag(int);
struct usermap *map_username(u8 *, u32);
u32 ip_find(u8 *);
int app_do_begin(struct msg_buff *, struct app_hdr *);
int app_do_end(struct msg_buff *, struct app_hdr *);
int make_ready_msg(u8 *, u8 *, u8 *, int);
int make_begin_msg(u8 *, u8 *, int);
void login(u8 *);
int app_do_ready(struct msg_buff *, struct app_hdr *);
void send_begin(u32, u8 *, int);
int app_do_data(struct msg_buff *, struct app_hdr *);
struct mfn * fn_find(u8 *, u8 *, int);
FILE * open_file(u8 *, int, u8 *);
struct mfn * mfn_create(u8 *, FILE *);
struct mfn * mfn_intern(struct mfn *, u8 *);
void printf_msg(char *msg,int bytes);
int make_datatrans_msg(u8 *, u8 *, int);
int make_end_msg();
void send_end_msg(u32 dest, u8 *filename, int slen);
#else
int app_do_login(struct msg_buff *, struct app_hdr *);
int do_frag(struct msg_buff * );
void send_msg(u8 *, int, struct sockaddr_in *, int);
void *worker_run(void *);
int make_fwd_login_msg(u8 *, u8 *, u32);
void send_fragments(struct list_head *, struct usermap *);
struct usermap *map_username(u8 *, u32, u16);
int make_reply_msg(u8 *, u8 *, u32, u8 *, int);
int app_do_exit(struct msg_buff *, struct app_hdr *);
int msg_forward(struct msg_buff *);
void free_mfq(struct mfq *);
int append_frag_head(int, struct msg_hdr *);
void printf_msg(char *msg,int bytes);
#endif

/* 分段重组的消息分段构成的hash链表 */
struct hlist_head mfq_hash[HQ_HASHSZ]; 
/* 参与分段重组的用户名与其ip地址映射关系表 */
struct hlist_head user_hash[HQ_HASHSZ];   
/* 进入非登录消息队列互斥锁 */
pthread_mutex_t mqlock_input = PTHREAD_MUTEX_INITIALIZER; 		
/* 登录用户队列互斥锁 */
pthread_mutex_t usrlock = PTHREAD_MUTEX_INITIALIZER; 		    
/* 外出分段消息队列互斥锁 */
pthread_mutex_t mqlock_frag = PTHREAD_MUTEX_INITIALIZER; 		
/* 记录日志互斥锁 */
pthread_mutex_t wrtloglock = PTHREAD_MUTEX_INITIALIZER; 		
/* 进入非登录消息队列条件变量 */
pthread_cond_t mqlock_input_ready = PTHREAD_COND_INITIALIZER;  	

#ifndef FORWARDER
pthread_t reasm_tid;   	    /* 分段重组工作线程id */
/* 登录消息队列互斥锁 */
pthread_mutex_t login_mqlock = PTHREAD_MUTEX_INITIALIZER; 		
/* 登录消息条件变量 */
pthread_cond_t login_mqlock_ready = PTHREAD_COND_INITIALIZER;   
/* 用于host的分段交互工作线程id */
pthread_t login_tid;                                      		
/* 创建登录消息队列 */
LIST_HEAD(login_msg_queue); 
/* 是否可以进行后续分段数据的发送互斥锁 */
pthread_mutex_t cont_lock = PTHREAD_MUTEX_INITIALIZER; 		    
/* 是否可以进行后续分段数据的发送条件变量 */
pthread_cond_t cont_lock_ready = PTHREAD_COND_INITIALIZER;      
#else
pthread_t tid;   		    /* 工作线程id */
#endif
struct app_opt{    /* 应用层消息处理函数 */
	int(*handler)(struct msg_buff * p_mbuf, struct app_hdr *ah);
};

/* 消息接收者可以同时接收的最大文件数量构成的hash链表 */
struct hlist_head fn_hash[HQ_HASHSZ];          
/* 用于存放可同时打开的文件描述符及对应用户名, 是fn_hash的节点 */
struct mfn {                                    				
	struct hlist_node hlist;
	u8 user[NAMESIZE];
	FILE *fp;
};

struct app_opt appl;

LIST_HEAD(frag_msg_queue);      /* 创建外出分段消息队列 */
LIST_HEAD(input_msg_queue);     /* 创建输入非登录消息队列 */
LIST_HEAD(user_queue);          /* 创建用户队列 */

LIST_HEAD(frag_queue);          /* 创建分段队列 */
LIST_HEAD(shuffled_frag_queue); /* 创建失序分段队列 */
LIST_HEAD(drop_queue); 		    /* 丢失分段队列 */
LIST_HEAD(mq_lru_list);         /* 创建分段重组垃圾回收队列 */
