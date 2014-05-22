#include "sys_xjob.h"
/*
 * TODO:
 */
asmlinkage extern long (*sysptr)(void *arg, int size);
asmlinkage long xjob(void *arg, int size)
{
	struct job *input = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	char *key = NULL;
	char *cipher = NULL;
	int ret = 0;
	bool repeat = false;
	if (arg == NULL) {
		printk(KERN_ERR "NULL passed as argument\n");
		return -EINVAL;
	}
	if (size + sizeof(int) != sizeof(struct job)) {
		printk(KERN_ERR "Invalid size %d from user\n", size);
		return -EINVAL;
	}
	mutex_lock(&lock);
	input = kmalloc(sizeof(struct job), GFP_KERNEL);
	if (!input) {
		ret = -ENOMEM;
		goto unlock;
	}
	if (copy_from_user(input, arg, size)) {
		printk(KERN_ERR "Error: Illegal memory address used\n");
		ret = -EFAULT;
		goto unlock;
	}
	if (input->type < ENCRT || input->type > REMOV) {
		ret = -EINVAL;
		goto unlock;
	}
	if (!(input->type == JLIST || input->type == REMOV)) {
		infile = getname(input->infile);
		if (IS_ERR(infile)) {
			ret = PTR_ERR(infile);
			goto unlock;
		}
	}
	input->infile = infile;
	if (input->type == ENCRT || input->type == DECRT
			|| input->type == CMPRS || input->type == DCMPRS) {
		outfile = getname(input->outfile);
		if (IS_ERR(outfile)) {
			ret = PTR_ERR(outfile);
			goto unlock;
		}
	}
	input->outfile = outfile;
	if ((input->type == ENCRT || input->type == DECRT)) {
		key = getname(input->key);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto unlock;
		}
		if (strlen(key) > 16) {
			ret = -EINVAL;
			goto unlock;
		}
	}
	input->key = key;
	if (input->type == CHKSM) {
		cipher = getname(input->cipher);
		if (IS_ERR(cipher)) {
			ret = PTR_ERR(cipher);
			goto unlock;
		}
	}
	input->cipher = cipher;
	/*if (qlen >= QLEN) {
		printk(KERN_INFO "Process waitqueued : %s (%d)\n",
			current->comm, current->pid);
		mutex_unlock(&lock);
		wait_event_interruptible(pwq, atomic_read(&pflag) == 1);
		atomic_set(&pflag, 0);
		goto begin;
	}*/
	input->id = job_id;
	ret = job_id;
	job_id++;
	if (input->type == JLIST) {
		struct jlist job[QLEN];
		struct queue *temp = head;
		int i = 0;
		for (i = 0; i < QLEN; i++) {
			job[i].id = -1;
			job[i].type = -1;
			job[i].pid = -1;
		}
		i = 0;
		while (temp != NULL) {
			job[i].id = temp->job->id;
			job[i].pid = temp->job->pid;
			job[i].type = temp->job->type;
			temp = temp->next;
			i++;
		}
		if (i == 0) {
			int send_err = -ENOENT;
			send_data_to_user(input->id, &send_err, sizeof(int),
							INT, input->pid);
		} else
			send_data_to_user(input->id, job,
				i*sizeof(struct jlist), LISTSTRUCT, input->pid);
	goto unlock;
	} else  if (input->type == REMOV) {
		int r_ret = remove_job_id(input->splopt);
		if (r_ret > 0) {
			int send_err = -EINTR;
			send_data_to_user(input->splopt,
					&send_err, sizeof(int), INT, r_ret);
			r_ret = 0;
		}
		send_data_to_user(input->id, &r_ret, sizeof(int), INT,
					input->pid);
		goto unlock;
	}
begin:
	if (repeat)
		mutex_lock(&lock);
	if (qlen >= QLEN) {
		/*
		 * Add this process to wait_queue of producer
		 * Reply back -EBUSY fi wait_queue is full
		 */
		printk(KERN_INFO "Process waitqueued : %s (%d)\n",
			current->comm, current->pid);
		mutex_unlock(&lock);
		wait_event_interruptible(pwq, atomic_read(&pflag) == 1);
		atomic_set(&pflag, 0);
		repeat = true;
		goto begin;
	}
	ret = add_job_to_queue(input);
unlock:
	mutex_unlock(&lock);
	if (ret >= 0 && input &&
		(input->type != JLIST || input->type != REMOV)) {
		if (waitqueue_active(&cwq)) {
			atomic_set(&cflag, 1);
			wake_up_interruptible(&cwq);
		}
	} else {
		cleanup_job(&input);
	}
	return ret;
}
int add_job_to_queue(struct job *newjob)
{
	int ret = 0;
	struct queue *queue;
	if (newjob->id < 0)
		return -EINVAL;
	queue = kmalloc(sizeof(struct queue), GFP_KERNEL);
	if (queue == NULL)
		return -ENOMEM;
	queue->job = newjob;
	queue->next = NULL;
	ret = newjob->id;
	if (tail == NULL) {
		printk(KERN_INFO "Starting queue\n");
		head = queue;
		tail = queue;
	} else {
		printk(KERN_INFO "Adding job to tail job : %d", tail->job->id);
		tail->next = queue;
		tail = tail->next;
	}
	qlen++;
	return ret;
}
int remove_job_id(int id)
{
	struct queue *prev = NULL;
	struct queue *temp = head;
	int ret = 0;
	if (head == NULL)
		return -ENOENT;
	else {
		while (temp && temp->job->id != id) {
			prev = temp;
			temp = temp->next;
		}
		if (temp != NULL) {
			ret = temp->job->pid;
			if (temp == head) {
				temp = head->next;
				cleanup_q(&head);
				head = temp;
				if (qlen == 1)
					tail = head;
			} else {
				prev->next = temp->next;
				if (tail == temp)
					tail = prev;
				cleanup_q(&temp);
			}
			qlen--;
		} else
			ret = -ENOENT;
	}
	return ret;
}
struct queue *remove_first_job(void)
{
	struct queue *ret = NULL;
	if (head != NULL) {
		ret = head;
		if (head == tail) {
			printk(KERN_INFO "Queue with single job\n");
			head = NULL;
			tail = NULL;
		} else {
			printk(KERN_INFO "Queue with multiple jobs\n");
			head = head->next;
		}
		qlen--;
	}
	return ret;
}
int process(struct job *job, char **opt)
{
	int ret = 0;
	msleep(5000);
	if (job == NULL)
		return -EINVAL;
	if (job->type == ENCRT) {
		ret = encrypt(job->infile, job->key, job->outfile);
	} else if (job->type == DECRT) {
		ret = decrypt(job->infile, job->key, job->outfile);
	} else if (job->type == CMPRS) {
		ret = compress(job->infile, job->outfile);
	} else if (job->type == DCMPRS) {
		ret = decompress(job->infile, job->outfile);
	} else if (job->type == CHKSM) {
		if (!strcmp(job->cipher, "MD5")) {
			*opt = kmalloc(sizeof(char)*33, GFP_KERNEL);
			if (*opt == NULL)
				return -ENOMEM;
			ret = checksum_md5(job->infile, *opt);
			if (ret == 0)
				ret = 33;
		} else if (!strcmp(job->cipher, "SHA1")) {
			*opt = kmalloc(sizeof(char)*41, GFP_KERNEL);
			if (*opt == NULL)
				return -ENOMEM;
			ret = checksum_sha1(job->infile, *opt);
			if (ret == 0)
				ret = 41;
		} else if (!strcmp(job->cipher, "CRC32C") ||
				!strcmp(job->cipher, "CRC32")) {
			int set = 1;
			*opt = kmalloc(sizeof(char)*33, GFP_KERNEL);
			if (*opt == NULL)
				return -ENOMEM;
			if (!strcmp(job->cipher, "CRC32"))
				set = 0;
			ret = checksum_crc32(job->infile, *opt, set);
			if (ret == 0)
				ret = 33;
		} else
			ret = -EINVAL;
	}
	return ret;
}
int encrypt(char *inputfile, u8 *key, char *outfile)
{
	struct crypto_cipher *tfm;
	int i, count, div, modd;
	int rbytes, wbytes;
	int inputsize = 0;
	mm_segment_t oldfs;
	/*u8 encrypted[16];*/
	char *encrypted = NULL;
	struct file *rfilp = NULL;
	int retval = 0;
	char *buf = NULL;
	struct file *temp = NULL;
	char *tmpkey;
	buf = kmalloc(16, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out;
	}
	encrypted = kmalloc(16, GFP_KERNEL);
	if (!encrypted) {

		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out1;

	}

	tmpkey = (char *)key;
	if (strlen(tmpkey) < 16) {
		for (i = strlen(tmpkey); i < 16; i++)
			tmpkey[i] = (char) 0;
		key = (u8 *)tmpkey;
	}
	rfilp = filp_open(inputfile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
			retval = (int) PTR_ERR(rfilp);
			goto out2;
	}
	if (!rfilp->f_op->read) {
		retval = (int) PTR_ERR(rfilp);
		goto out2;
	}
	temp = filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC, 655);
	if (!temp || IS_ERR(temp)) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error : Opening output file ");
		goto out3;
	}
	if (!temp->f_op->write) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error: File doesn't allow writes");
		goto out3;
	}
	inputsize = rfilp->f_dentry->d_inode->i_size;
	div = inputsize/AES_BLOCK_SIZE;
	modd = inputsize%AES_BLOCK_SIZE;
	if (modd > 0)
		div++;
	count = div;
	tfm = crypto_alloc_cipher("aes", 0, AES_BLOCK_SIZE);
	crypto_cipher_setkey(tfm, key, 16);
	rfilp->f_pos = 0;
	temp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	for (i = 0; i < count; i++) {
		rbytes = vfs_read(rfilp, buf, AES_BLOCK_SIZE, &rfilp->f_pos);
		if (rbytes < 0) {
			printk(KERN_ERR "\n Error:reading input file");
			retval = rbytes;
			goto out4;
		}
		if (rbytes < 16)
			buf[rbytes] = (char) 3;
		crypto_cipher_encrypt_one(tfm, encrypted, buf);
		wbytes = vfs_write(temp, encrypted, 16, &temp->f_pos);
		if (wbytes < 0) {
			printk(KERN_ERR "\n Error:writing input file");
			goto out4;
		}
	}
	set_fs(oldfs);
	crypto_free_cipher(tfm);
out4:
	filp_close(temp, NULL);
out3:
	filp_close(rfilp, NULL);
out2:
	kfree(encrypted);
out1:
	kfree(buf);
out:
	return	retval;
}

int  compress(char *inputfile, char *outfile)
{
	struct crypto_comp *tfm2;
	int rbytes, wbytes;
	mm_segment_t oldfs;
	struct file *rfilp = NULL;
	struct file *temp = NULL;
	int retval = 0;
	char *inbuf;
	char *outbuf;
	int outlen, m = 0, c = 0, o, g;
	int length[10];
	char *buf2;
	int count;
	int temp1;
	int master_count = 0;
	inbuf = kmalloc(PAGE_SIZE_CHUNK, GFP_KERNEL);
	if (!inbuf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out;
	}
	outbuf = kmalloc(PAGE_SIZE_CHUNK, GFP_KERNEL);
	if (!outbuf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out1;
	}
	buf2 = kmalloc(20, GFP_KERNEL);
	if (!buf2) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out2;
	}
	rfilp = filp_open(inputfile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
			printk("\n Error: Opening input files ");
			retval = (int) PTR_ERR(rfilp);
			goto out3;
	}
	if (!rfilp->f_op->read) {
		retval = (int) PTR_ERR(rfilp);
		printk("\n Error: File doesn't allow reads.");
		goto out3;
	}
	temp = filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC, 655);
	if (!temp || IS_ERR(temp)) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error : Opening output file ");
		goto out4;
	}
	if (!temp->f_op->write) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error: File doesn't allow writes");
		goto out4;
	}
	tfm2 = crypto_alloc_comp("deflate", 0, 0);
	if (!tfm2) {
		retval = -EINVAL;
		printk(KERN_ERR "\n Error: problem with tfm");
	}
	rfilp->f_pos = 0;
	temp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	do {
		rbytes = vfs_read(rfilp, inbuf, PAGE_SIZE_CHUNK,
					&rfilp->f_pos);
		if (rbytes < 0) {
			printk(KERN_ERR "\n Error:reading input file");
			retval = rbytes;
			goto out5;
		}
		retval = crypto_comp_compress(tfm2, inbuf, rbytes,
							outbuf, &outlen);
		if (retval < 0) {
			printk(KERN_ERR "\n Error:Compression failed");
			goto out5;
		}
		length[m] = outlen;
		wbytes = vfs_write(temp, outbuf, outlen, &temp->f_pos);
		if (wbytes < 0) {
			printk(KERN_ERR "\n Error:writing output file");
			goto out5;
		}
		++m;
	} while (rbytes >= PAGE_SIZE_CHUNK);
/*Add lengths of data chunks of compressed data into array*/
	for (c = 0; c < m; ++c) {
		temp1 = length[c];
		o = length[c];
		while (o > 0) {
			count = 0;
			while (temp1 != 0) {
				count++;
				temp1 /= 10;
		}
		count = master_count + count;
		master_count = count;
		while (o > 0) {
			--count;
			g = o % 10;
			buf2[count] = (char) ('0' + g);
			o = o/10;
		}
		/*End of single length parameter in buffer*/
		buf2[master_count] = 'X';
		master_count++;
	}
}
	/*End of length parameters indication*/
	buf2[master_count] = 'Z';
	/*Write the buffer having lengths of comprssed data
		chunks to end of compressed file*/
	wbytes = vfs_write(temp, buf2, 20, &temp->f_pos);
	if (wbytes < 0) {
		printk(KERN_ERR "\n Error:writing output file");
		goto out5;
	}
	set_fs(oldfs);
out5:
	filp_close(temp, NULL);
out4:
	filp_close(rfilp, NULL);
out3:
	kfree(buf2);
out2:
	kfree(outbuf);
out1:
	kfree(inbuf);
out:
	return retval;
}
int  decompress(char *inputfile, char *outfile)
{
	struct crypto_comp *tfm2;
	int rbytes, wbytes;
	mm_segment_t oldfs;
	struct file *rfilp = NULL;
	int retval = 0;
	char *inbuf;
	char *outbuf;
	struct file *temp = NULL;
	int complen[10];
	int arraysize = 0;
	char num[10];
	long nbr;
	int l = 0;
	int t = 0;
	int plen;
	int j = 0, compsize = 0;
	char *newbuf = NULL;
	tfm2 = crypto_alloc_comp("deflate", 0, 0);
	if (!tfm2) {
		retval = -EINVAL;
		printk(KERN_ERR "\n Error: problem with tfm");
	}
	inbuf = kmalloc(PAGE_SIZE_CHUNK, GFP_KERNEL);
	if (!inbuf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out;
	}
	outbuf = kmalloc(PAGE_SIZE_CHUNK, GFP_KERNEL);
	if (!outbuf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out1;
	}
	newbuf = kmalloc(20, GFP_KERNEL);
	if (!newbuf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out2;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	rfilp = filp_open(inputfile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
			printk("\n Error: Opening input files ");
			retval = (int) PTR_ERR(rfilp);
			goto out3;
	}
	if (!rfilp->f_op->read) {
		retval = (int) PTR_ERR(rfilp);
		printk("\n Error: File doesn't allow reads.");
		goto out3;
	}
	temp = filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC, 655);
	if (!temp || IS_ERR(temp)) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error : Opening output file ");
		goto out4;
	}
	if (!temp->f_op->write) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error: File doesn't allow writes");
		goto out4;
	}
	rfilp->f_pos = 0;
	temp->f_pos = 0;
	compsize = rfilp->f_dentry->d_inode->i_size;
	rfilp->f_pos = vfs_llseek(rfilp, (loff_t) compsize-20, SEEK_SET);
	rbytes = vfs_read(rfilp, newbuf, 20,
					&rfilp->f_pos);
	for (j = 0; j < 20; ++j) {
		if (newbuf[j] == 'Z')
			break;
		if (newbuf[j] != 'X') {
			num[l] = newbuf[j];
			++l;
		} else {
			int t_err = 0;
			num[l] = '\0';
			t_err = kstrtol(num, 10, &nbr);
			complen[t] = (int) nbr;
			++arraysize;
			l = 0;
			++t;
		}
	}
rfilp->f_pos = 0;
temp->f_pos = 0;
for (l = 0 ; l < arraysize; ++l) {
	rbytes = vfs_read(rfilp, inbuf, complen[l],
					&rfilp->f_pos);
	if (rbytes < 0) {
		printk(KERN_ERR "\n Error:reading input file");
		retval = rbytes;
		goto out5;
	}
	retval = crypto_comp_decompress(tfm2, inbuf, rbytes, outbuf, &plen);
	if (retval < 0) {
		printk(KERN_ERR "\n Error:Compression failed");
		goto out5;
	}
	wbytes = vfs_write(temp, outbuf, plen, &temp->f_pos);
	if (wbytes < 0) {
		printk(KERN_ERR "\n Error:writing output file");
		goto out5;
	}
}
out5:
	filp_close(temp, NULL);
out4:
	filp_close(rfilp, NULL);
out3:
	kfree(newbuf);
out2:
	kfree(outbuf);
out1:
	kfree(inbuf);
out:
	return retval;
}
int decrypt(char *infile, u8 *key, char *outfile)
{
	struct crypto_cipher *tfm;
	int i, count, div, modd;
	int rbytes, wbytes;
	int inputsize = 0;
	mm_segment_t oldfs;
	/*u8 decrypted[16];*/
	char *decrypted = NULL;
	struct file *rfilp = NULL;
	int retval = 0;
	void *buf;
	char *tmpkey;
	struct file *temp = NULL;
	buf = kmalloc(16, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error: problem with memory allocation");
		goto out;
	}
	decrypted = kmalloc(16, GFP_KERNEL);
	if (!decrypted) {
		retval = -ENOMEM;
		printk(KERN_ERR "\n Error:problem with memory allocation");
		goto out1;
	}

	tmpkey = (char *)key;
	if (strlen(tmpkey) < 16) {
		for (i = strlen(tmpkey); i < 16; i++)
			tmpkey[i] = (char) 0;
		key = (u8 *)tmpkey;
	}

	rfilp = filp_open(infile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
			retval = (int) PTR_ERR(rfilp);
			goto out2;
		}
		if (!rfilp->f_op->read) {
			retval = (int) PTR_ERR(rfilp);
			goto out2;
		}
	temp = filp_open(outfile, O_RDWR | O_CREAT | O_TRUNC, 655);
	if (!temp || IS_ERR(temp)) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error : Opening output file ");
		goto out3;
	}
	if (!temp->f_op->write) {
		retval = (int) PTR_ERR(temp);
		printk(KERN_ERR "\n Error: File doesn't allow writes");
		goto out3;
	}
	inputsize = rfilp->f_dentry->d_inode->i_size;
	div = inputsize/AES_BLOCK_SIZE;
	modd = inputsize%AES_BLOCK_SIZE;
	if (modd > 0)
		div++;
	count = div;
	tfm = crypto_alloc_cipher("aes", 0, 16);
	crypto_cipher_setkey(tfm, key, 16);
	rfilp->f_pos = 0;
	temp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	for (i = 0; i < count; i++) {
		rbytes = vfs_read(rfilp, buf, 16, &rfilp->f_pos);
		if (rbytes < 0) {
			retval = rbytes;
			goto out4;
		}
		crypto_cipher_decrypt_one(tfm, decrypted, buf);
		if (i == count - 1) {
			int z;
			for (z = 0; z < 16; ++z) {
				if (decrypted[z] == (char) 3) {
					rbytes = z;
					break;
				}
			}
		}
		wbytes = vfs_write(temp, decrypted, rbytes, &temp->f_pos);
		if (wbytes < 0) {
			retval = wbytes;
			goto out4;
		}
	}
	set_fs(oldfs);
	crypto_free_cipher(tfm);
out4:
	filp_close(temp, NULL);
out3:
	filp_close(rfilp, NULL);
out2:
	kfree(decrypted);
out1:
	kfree(buf);
out:
	return retval;
}

int checksum_crc32(char *infile, char *chksum, int type)
{
	u32 crc = ~0;
	int ret = 0;
	struct file *file = NULL;
	if (chksum == NULL)
		return -EINVAL;
	if (!(type == 1 || type == 0))
		return -EINVAL;
	file = filp_open(infile, O_RDONLY, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		printk(KERN_INFO "Unable to open file\n");
		file = NULL;
	} else {
		int rb = 0;
		void *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		do {
			rb = vfs_read(file, buf, PAGE_SIZE, &(file->f_pos));
			if (rb > 0) {
				if (type == 0)
					crc = crc32(crc, buf, rb);
				else if (type == 1)
					crc = crc32c(crc, buf, rb);
			} else
				ret = rb;
		} while (rb > 0);
		sprintf(chksum, "%u", crc);
		filp_close(file, NULL);
	}
	return ret;
}

int checksum_md5(char *inputfile, char *chksum)
{
	int retval = 0, rbytes = 0, seglen = 0;
	struct file *rfilp;
	mm_segment_t oldfs;
	void *buf = NULL;
	char *digest = NULL;
	int err, i, ret;
	struct hash_desc desc;
	struct crypto_hash *tfm;
	struct scatterlist sg;

	/*ERROR CHECK*/
	if (chksum == NULL) {
		printk(KERN_ERR "Error: Checksum is NULL\n");
		retval = -EINVAL;
		goto out;
	}
	rfilp = filp_open(inputfile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
		printk(KERN_ERR "Error: Opening input files\n");
		retval = (int) PTR_ERR(rfilp);
		goto out;
	}
	if (!rfilp->f_op->read) {
		retval = (int) PTR_ERR(rfilp);
		printk(KERN_ERR "Error: File doesn't allow reads.\n");
		goto out;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	digest = kzalloc((MD5_SIGNATURE_SIZE+1)
		* sizeof(char), GFP_KERNEL);

	rfilp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "Error: Unable to allocate memory to struct crypto_alloc_hash\n");
		err = PTR_ERR(tfm);
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;
	ret = crypto_hash_init(&desc);
	if (retval < 0) {
		printk(KERN_ERR "Error: crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
	}
	do {
		rbytes = vfs_read(rfilp, buf, PAGE_SIZE, &rfilp->f_pos);
		if (rbytes < 0) {
			retval = rbytes;
			goto out;
		}
		seglen = rbytes;
		sg_init_one(&sg, (void *) buf, seglen);
		retval = crypto_hash_update(&desc, &sg, seglen);
		if (retval < 0) {
			printk(KERN_ERR "Error: crypto_hash_update() failed for id\n");
			crypto_free_hash(tfm);
			retval = -EINVAL;
			goto cleanup;
		}
		if (rbytes < PAGE_SIZE) {
			retval = crypto_hash_final(&desc, digest);
			if (retval < 0) {
				printk(KERN_ERR "Error: crypto_hash_final() failed for sever digest\n");
				crypto_free_hash(tfm);
				retval = -EINVAL;
				goto cleanup;
			}
		}
	} while (rbytes >= PAGE_SIZE);

	if (digest == NULL) {
		printk(KERN_ERR "Error: Digest is NULL\n");
		retval = -1;
		goto out;
	}
	for (i = 0; i < 16; i++)
		sprintf((chksum + i*2), "%02x", digest[i] & 0xFF);
cleanup:
	crypto_free_hash(tfm);
	kfree(digest);
	kfree(buf);
	set_fs(oldfs);
	filp_close(rfilp, NULL);
out:
	return retval;
}

int checksum_sha1(char *inputfile, char *chksum)
{
	int retval = 0, rbytes = 0, seglen = 0;
	struct file *rfilp;
	mm_segment_t oldfs;
	void *buf = NULL;
	char *digest = NULL;
	int err, i, ret;
	struct hash_desc desc;
	struct crypto_hash *tfm;
	struct scatterlist sg;

	/*ERROR CHECK */
	if (chksum == NULL) {
		printk(KERN_ERR "Checksum is NULL\n");
		retval = -EINVAL;
		goto out;
	}
	rfilp = filp_open(inputfile, O_RDONLY, 0);
	if (!rfilp || IS_ERR(rfilp)) {
		printk(KERN_ERR "Error: Opening input files\n");
		retval = (int) PTR_ERR(rfilp);
		goto out;
	}
	if (!rfilp->f_op->read) {
		retval = (int) PTR_ERR(rfilp);
		printk(KERN_ERR "Error: File doesn't allow reads.\n");
		goto out;
	}
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	digest = kzalloc((SHA1_SIGNATURE_SIZE+1)
			* sizeof(char), GFP_KERNEL);

	rfilp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "Unable to allocate struct srypto_hash\n");
		err = PTR_ERR(tfm);
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;
	ret = crypto_hash_init(&desc);
	if (retval < 0) {
		printk(KERN_ERR "crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
	}

	do {
		rbytes = vfs_read(rfilp, buf, PAGE_SIZE, &rfilp->f_pos);
		if (rbytes < 0) {
			retval = rbytes;
			goto out;
		}
		seglen = rbytes;
		sg_init_one(&sg, (void *) buf, seglen);
		retval = crypto_hash_update(&desc, &sg, seglen);
		if (retval < 0) {
			printk(KERN_ERR "crypto_hash_update() failed for id\n");
			crypto_free_hash(tfm);
			retval = -EINVAL;
			goto cleanup;
		}
		if (rbytes < PAGE_SIZE) {
			retval = crypto_hash_final(&desc, digest);
			if (retval < 0) {
				printk(KERN_ERR "crypto_hash_final() failed for sever digest");
				crypto_free_hash(tfm);
				retval = -EINVAL;
				goto cleanup;
			}
		}
	} while (rbytes >= PAGE_SIZE);
	if (digest == NULL) {
		printk(KERN_ERR "Digest is NULL\n");
		retval = -1;
		goto out;
	}
	for (i = 0; i < 20; i++)
		sprintf((chksum + i*2), "%02x", digest[i] & 0xFF);

cleanup:
	crypto_free_hash(tfm);
	kfree(digest);
	kfree(buf);
	set_fs(oldfs);
	filp_close(rfilp, NULL);
out:
	return retval;
}
void cleanup_job(struct job **job)
{
	if (*job != NULL) {
		if ((*job)->infile != NULL)
			putname((*job)->infile);
		if ((*job)->outfile != NULL)
			putname((*job)->outfile);
		if ((*job)->key != NULL)
			putname((*job)->key);
		if ((*job)->cipher != NULL)
			putname((*job)->cipher);
		kfree(*job);
		*job = NULL;
	}
}
void cleanup_q(struct queue **q)
{
	if (*q != NULL) {
		if ((*q)->job != NULL)
			cleanup_job(&((*q)->job));
		kfree(*q);
		*q = NULL;
	}
}

int work(void *data)
{
	struct queue *q = NULL;
	int ret = 0;
	int pid = 0;
	int id = 0;
	char *opt = NULL;
restart:
	printk(KERN_INFO "Work started by worker %s (%d)\n",
		current->comm, current->pid);
	q = NULL;
	ret = 0;
	mutex_lock(&lock);
	if (!destroy) {
		if (qlen == 0) {
			mutex_unlock(&lock);
			printk(KERN_INFO "Process %s (%d) being added "
				"to waitqueue\n", current->comm, current->pid);
			wait_event_interruptible(cwq, atomic_read(&cflag) == 1);
			atomic_set(&cflag, 0);
			goto restart;
		}
		q = remove_first_job();
	}
	mutex_unlock(&lock);
	if (q != NULL) {
		if (waitqueue_active(&pwq)) {
			printk(KERN_INFO "Process removed from waitqueue by "
				"%s (%d)\n", current->comm, current->pid);
			atomic_set(&pflag, 1);
			wake_up_interruptible(&pwq);
		}
		printk(KERN_INFO "Process %s (%d) start processing job %d\n",
				current->comm, current->pid, q->job->id);
		ret = process(q->job, &opt);
		id = q->job->id;
		pid = q->job->pid;
		cleanup_q(&q);
	}
	mutex_lock(&lock);
	if (ret <= 0) {
		send_data_to_user(id, &ret, sizeof(int), INT, pid);
	} else {
		send_data_to_user(id, opt, ret, CHAR, pid);
		kfree(opt);
		opt = NULL;
	}
	if (!destroy) {
		mutex_unlock(&lock);
		schedule();
		goto restart;
	} else {
		atomic_set(&cflag, 1);
		wake_up_interruptible(&cwq);
	}
	mutex_unlock(&lock);
	printk(KERN_INFO "Destroying process %s (%d)\n",
		current->comm, current->pid);
	do_exit(0);
}
int send_signal_to_job(int ret, int pid)
{
	struct siginfo info;
	struct task_struct *t;
	int err = 0;
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIG_TEST;
	info.si_code = SI_QUEUE;
	info.si_int = ret;
	t = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if (t == NULL)
		err = -ESRCH;
	else
		err = send_sig_info(SIG_TEST, &info, t);
	return err;
}
int send_data_to_user(int id, void *res, int size, int type, int pid)
{
	int ret = 0;
	struct job_res result;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	struct task_struct *t = pid_task(find_pid_ns(pid, &init_pid_ns),
				PIDTYPE_PID);
	if (t == NULL || pid == 0) {
		printk(KERN_INFO "No such process %d to communicate\n", pid);
		return -ESRCH;
	}
	result.id = id;
	memset(&result.result, 0, MAX_SIZE);
	memcpy(&result.result, res, size);
	result.size = size;
	result.type = type;
	skb = alloc_skb(NLMSG_SPACE(MAX_PAYLOAD), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	ret = -EINVAL;
	nlh = NLMSG_PUT(skb, 0, 0, 0, MAX_PAYLOAD);
	memcpy(NLMSG_DATA(nlh), &result, 2*sizeof(struct job_res));
	ret = netlink_unicast(socket, skb, pid, 0);
	if (ret < 0)
		goto nlmsg_failure;
	return ret;
nlmsg_failure: /* Required by NLMSG_PUT */
	kfree_skb(skb);
	return ret;
}
void destroy_queue(void)
{
	struct queue *q;
	printk(KERN_INFO "Destroying queue\n");
	while (head != NULL) {
		q = head;
		head = head->next;
		kfree(q->job);
		kfree(q);
	}
	tail = NULL;
	qlen = 0;
}
void destroy_workers(void)
{
	/*
	 * If all are in queue, atleast one consumer should be woken up
	 * The other threads will be woken up in the thread itself
	 */
	if (waitqueue_active(&cwq)) {
		atomic_set(&cflag, 1);
		wake_up_interruptible_sync(&cwq);
	}
}
void xjob_callback(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	if (skb == NULL) {
		printk(KERN_INFO "skb is NULL\n");
		return ;
	}
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "%s: received netlink message payload: %s\n",
		__func__, (char *) NLMSG_DATA(nlh));
}
static int __init init_sys_xjob(void)
{
	int i = 0;
	int ret = 0;
	printk(KERN_INFO "installed new sys_xjob module\n");
	if (sysptr == NULL) {
		sysptr = xjob;
		/* Initialize workqueue */
		head = NULL;
		tail = NULL;
		qlen = 0;
		/* Create netlink socket for user-kernel communication
		 * Report BUG if socket can't be created as rtnetlink is
		 * important subsystem of linux kernel
		 */
		socket = netlink_kernel_create(&init_net, NETLINK_TEST, 0,
				xjob_callback, NULL, THIS_MODULE);
		BUG_ON(socket == NULL);
		/* Initialize lock for workqueue */
		mutex_init(&lock);
		/* Create worker threads */
		for (i = 0; i < NUM_THREADS; i++) {
			worker[i] = kthread_create(work, NULL,
						"consumer_%d", i);
			/* STUB: Handle when threads are not created */
			if (IS_ERR(worker[i])) {
				printk(KERN_ERR "Thread could not be created\n");
				ret = PTR_ERR(worker[i]);
				worker[i] = NULL;
				goto error;
			}
		}
		/*
		 * Initialize wait queues for both xjob and worker
		 * Used during throttling the excessive requests
		 */
		 init_waitqueue_head(&pwq);
		 init_waitqueue_head(&cwq);
		 atomic_set(&pflag, 0);
		 job_id = 0;
		 atomic_set(&cflag, 0);
		 destroy = false;
		 for (i = 0; i < NUM_THREADS; i++)
			wake_up_process(worker[i]);
	}
error:
	if (ret) {
		/* Stop all the started threads */
		for (i = 0; NUM_THREADS; i++) {
			if (worker[i] != NULL)
				kthread_stop(worker[i]);
		}
		if (socket != NULL)
			sock_release(socket->sk_socket);
	}
	return ret;
}
static void  __exit exit_sys_xjob(void)
{
	if (sysptr != NULL) {
		mutex_lock(&lock);
		destroy_queue();
		/*if (head != NULL) {
			printk(KERN_INFO "Module is in use\n");
			mutex_unlock(&lock);
			return -EBUSY;
		}*/
		destroy = true;
		mutex_unlock(&lock);
		destroy_workers();
		sock_release(socket->sk_socket);
		sysptr = NULL;
	}
	printk(KERN_INFO "removed sys_xjob module\n");
}
module_init(init_sys_xjob);
module_exit(exit_sys_xjob);
MODULE_LICENSE("GPL");
