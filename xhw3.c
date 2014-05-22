#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#define __NR_xjob 349
#define __user
#define SIG_TEST 44
#define NETLINK_TEST 17
#define MAX_PAYLOAD 2048
#define INT 0
#define CHARARR 1
#define LISTSTRUCT 2
#define TYPE(x) (x == 0 ? int : (x == 1 ? char : struct jlist))

int main()
{
	struct job {
		int pid;
		__user char *infile;
		__user char *outfile;
		char *key;
		char *cipher;
		int type;
		int splopt;
	};
	struct job_res {
		int id;
		char result[120];
		int size;
		int type; /* 0 int, 1 char*, 2 list structure */
	} result;
	struct jlist {
		unsigned int id;
		int pid;
		int type;
	};
	/* Read message from kernel */

	struct job job[15];
	int input_size = sizeof(struct job);
	int i = 0;
	int rc = 0;
	int err = 0;
	struct sockaddr_nl s_nladdr, d_nladdr;
	struct msghdr msg ;
	struct nlmsghdr *nlh = NULL ;
	struct iovec iov;
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);

	/* source address */
	memset(&s_nladdr, 0, sizeof(s_nladdr));
	s_nladdr.nl_family = AF_NETLINK ;
	s_nladdr.nl_pad = 0;
	s_nladdr.nl_pid = getpid();
	bind(fd, (struct sockaddr *)&s_nladdr, sizeof(s_nladdr));

	/* destination address */
	memset(&d_nladdr, 0, sizeof(d_nladdr));
	d_nladdr.nl_family = AF_NETLINK ;
	d_nladdr.nl_pad = 0;
	d_nladdr.nl_pid = 0; /* destined to kernel */

	/* Fill the netlink message header */
	nlh = (struct nlmsghdr *)malloc(MAX_PAYLOAD);
	memset(nlh , 0 , MAX_PAYLOAD);
	strcpy(NLMSG_DATA(nlh), " Mr. Kernel, Are you ready ?");
	nlh->nlmsg_len = MAX_PAYLOAD;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 1;
	nlh->nlmsg_type = 0;

	/*iov structure */

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	/* msg */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *) &d_nladdr ;
	msg.msg_namelen = sizeof(d_nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sendmsg(fd, &msg, 0);
	printf("process pid = %d\n", getpid());
	for (i = 0; i < 10; i++) {
		job[i].pid = getpid();
		if (i == 0) {
			job[i].type = 5;
			job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
			job[i].cipher = "CRC32C";
			job[i].outfile = "/usr/src/hw3-cse506g17/hw3/new";
		} else if (i == 1) {
			job[i].type = 5;
			job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
			job[i].cipher = "CRC32";
		} else if (i == 2) {
			job[i].type = 5;
			job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
			job[i].cipher = "SHA1";
		} else if (i == 3) {
			job[i].type = 5;
			job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
			job[i].cipher = "MD5";
		} else if (i == 4) {
			job[i].type = 1;
			job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
			job[i].outfile = "/usr/src/hw3-cse506g17/hw3/encrypt.txt";
			job[i].key = "Akhilesh";
		} else if (i == 5) {
                        job[i].type = 3;
                        job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
                        job[i].outfile = "/usr/src/hw3-cse506g17/hw3/compress.txt";
                } else if (i == 6) {
                        job[i].type = 2;
                        job[i].infile = "/usr/src/hw3-cse506g17/hw3/encrypt.txt";
                        job[i].outfile = "/usr/src/hw3-cse506g17/hw3/decrypt.txt";
                        job[i].key = "Akhilesh";
                } else if (i == 7) {
                        job[i].type = 4;
                        job[i].infile = "/usr/src/hw3-cse506g17/hw3/compress.txt";
                        job[i].outfile = "/usr/src/hw3-cse506g17/hw3/decompress.txt";
                } else if (i == 9) {
			job[i].type = 6;
		} else {
			job[i].type = 5;
			job[i].infile = "/usr/src/hw3-cse506g17/hw3/sample.txt";
			job[i].cipher = "CRC32";
			//job[i].splopt = 7;	
		}
		rc = syscall(__NR_xjob, &job[i], input_size);
		if (rc == 0)
			printf("syscall returned %d\n", rc);
		else
			printf("syscall returned %d (errno=%d)\n", rc, errno);
	}
	i = 0;
	while (i != 10) {
		memset(nlh, 0, MAX_PAYLOAD);
		err = recvmsg(fd, &msg, 0);
		if (err <= 0)
			continue;
		i++;
		printf("err value = %d size of payload = %d\n",
						err, MAX_PAYLOAD);
		memcpy(&result, NLMSG_DATA(nlh), sizeof(struct job_res));
		if (result.type == 0)
			printf("Received message payload: id = %d and"
				"result = %d\n", result.id,
					(int)*(result.result));
		else if (result.type == 2) {
			int j = 0;
			struct jlist  res1[10];
			memcpy(res1, &result.result, result.size);
			printf("Received message payload: id = %d and size ="
					"%d\n", result.id, result.size);
			printf("List of jobs :\n");
			for (j = 0; j < result.size/sizeof(struct jlist); j++) {
				printf("id = %d\tpid = %d\ttype = %d\n",
					res1[j].id, res1[j].pid, res1[j].type);
			}
			printf("\n");
		} else if (result.type == 1) {
			char res2[41];
			memcpy(res2, &result.result, result.size);
			printf("Received message payload: id = %d and"
					"result = %s\n", result.id, res2);
		}
	}
	close(fd);
	return 0;
}
