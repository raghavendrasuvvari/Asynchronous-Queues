#ifndef XJOB
#define XJOB
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/netlink.h>
#include <linux/init.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/crc32.h>
#include <linux/crc32c.h>


#define ENCRT	1
#define DECRT	2
#define CMPRS	3
#define DCMPRS	4
#define CHKSM	5
#define JLIST	6
#define REMOV	7

#define QLEN 10
#define NETLINK_TEST  17
#define SIG_TEST 44

#define NUM_THREADS 1
#define MAX_PAYLOAD 2048
#define MAX_SIZE (sizeof(int)*3*QLEN > sizeof(char)*41 ?\
		 sizeof(int)*3*QLEN : sizeof(char)*41)
#define AES_BLOCK_SIZE 16
#define PAGE_SIZE_CHUNK 4096
#define MD5_SIGNATURE_SIZE 16
#define SHA1_SIGNATURE_SIZE 20

#define INT 0
#define CHAR 1
#define LISTSTRUCT 2

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

struct job {
	int pid;
	char *infile;
	char *outfile;
	char *key;
	char *cipher;
	int type;
	int splopt;
	unsigned int id;
};
struct jlist {
	unsigned int id;
	int pid;
	int type;
};
struct queue {
	struct job *job;
	struct queue *next;
};
struct job_res {
	int id;
	char result[MAX_SIZE];
	int size;
	int type; /* 0 int, 1 char*, 2 jlist structure */
};

static struct queue *head;
static struct queue *tail;
static int qlen;
static struct mutex lock;
static struct task_struct *worker[NUM_THREADS] = {NULL};
static wait_queue_head_t pwq;
static wait_queue_head_t cwq;
static unsigned int job_id;
static atomic_t pflag = ATOMIC_INIT(0);
static atomic_t cflag = ATOMIC_INIT(0);
static bool destroy;
static struct sock *socket;


int add_job_to_queue(struct job *newjob);
struct queue *remove_first_job(void);
void destroy_queue(void);
void destroy_workers(void);
int send_signal_to_job(int ret, int pid);
int send_data_to_user(int id, void *ret, int size, int type, int pid);
void xjob_callback(struct sk_buff *skb);
int remove_job_id(int id);
int checksum_crc32(char *infile, char* chksum, int type);
int checksum_md5(char *inputfile, char *chksum);
int checksum_sha1(char *inputfile, char *chksum);
int encrypt(char *inputfile, u8 *key1, char *outfile);
int decrypt(char *infile, u8 *key1, char *outfile);
int compress(char *infile, char *outfile);
int decompress(char *infile, char *outfile);
void cleanup_job(struct job **job);
void cleanup_q(struct queue **q);
#endif
