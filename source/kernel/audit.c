/*
# The CloudArmor additions are ...
#
#  Copyright (c) 2016 The Pennsylvania State University
#  Systems and Internet Infrastructure Security Laboratory
#
# they were developed by:
#
#  Yuqiong Sun          <yus138@cse.psu.edu>
#  Giuseppe Petracca    <gxp18@cse.psu.edu>
#  Trent Jaeger         <tjaeger@cse.psu.edu>
#
# Unless otherwise noted, all code additions are ...
#
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  * http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.
*/

/*
* Sample LSM implementation
*/

//#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <linux/stat.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for sysctl_local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <asm/uaccess.h>
//#include <asm/semaphore.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/debugfs.h>
#include <linux/uio.h>
#include <crypto/hash.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include "ndfsa.h"

typedef struct task_security_struct {
  u32 parent_flag;
  u32 child_flag;
} task_security_struct;

typedef struct socket_security_struct {
  u32 libvirt_flag;
} socket_security_struct;

typedef struct pipe_security_struct {
  u32 pipe_flag;
} pipe_security_struct;


MODULE_LICENSE("GPL");

#define INITCONTEXTLEN 100
#define XATTR_SAMPLE_SUFFIX "sample"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

#define PATHLEN 128

#define SAMPLE_IGNORE 0
#define SAMPLE_UNTRUSTED 1
#define SAMPLE_TRUSTED 2

/* Name size definitions */
#define NAME_SIZE 50
//#define STATE_FINISH 0
//#define STATE_ERROR 1
//#define STATE_ONGOING 2

extern struct security_operations *security_ops;
extern state *states;
extern int current_state;
extern int state_count;
extern int policy_flag;
extern int arg_count;
extern argument *arguments;

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
	} ptr;
#endif
};

/*
typedef struct event{
  char name[NAME_SIZE];
}event;
*/
typedef struct event{
	char* value;
	int size;
	int type;
}event;

u32 tee_flag;
u32 iptsave_flag;
u32 iptrestore_flag;
event *current_event;
u32 echo_flag;
struct timespec ts;
//int model_state;

static int tss_copy(task_security_struct *old, task_security_struct *new)
{
	new->parent_flag = old->parent_flag;
	new->child_flag = old->child_flag;
	return 0;
}


static void print_buffer(char __user *address, int count, int flag)
{
	int i;
	char * msg;
	char read_f[] = "read";
	char write_f[] = "write";

	if (flag == 0) msg = read_f;
	else msg = write_f;

	printk("CloudArmor: message %s: ", msg);
	for(i=0; i<count; i++)
	{
		unsigned char x = *(address+i);
		if((int)x <= 126 && (int)x >= 33)
		{
			printk("%c", x);
		}
		else
		{
			printk("\\%d", (int)x);
		}
	}
	printk("\n");
}

static int cloudarmor_copy_from_user(char *to, struct iovec *iov, unsigned long len, unsigned long nr_segs)
{
	unsigned long copy;
	size_t i = 0;
	int j = 0;
	char * temp;

	//memcpy(to , iov->iov_base, iov->iov_len);

	for(i = 0; i < nr_segs; i++)
	{
		temp = (char __user *)iov[i].iov_base;
		for(j=0; j<iov[i].iov_len; j++)
		{
			if(temp[j] == '\n')
				to[j] = '|';
			else
				to[j] = temp[j];
		}
	}

	return 0;
}

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

static int count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i++ >= max)
				return -E2BIG;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

static int split_string(char *symbol, char *source, char *dest, char **filename, char **sha1sum)
{
	// Extract filename from event argument
	int i = 0;
	char *prefix;
	char *suffix;
	char *cur = kzalloc(strlen(source)+1, GFP_KERNEL);
	char *token = cur;
	memcpy(cur, source, strlen(source));

	while(token = strsep(&cur, symbol))
	{
		//printk(KERN_WARNING "CloudArmor: Token is %s", token);
		if(i == 0)
		{
			if(strlen(token) == 0)
			{
				prefix = NULL;
			}
			else
			{
				prefix = kzalloc(strlen(token)+1, GFP_KERNEL);
				if(!prefix) return -ENOMEM;
				memcpy(prefix, token, strlen(token)+1);
			}

		}
		if(i == 1)
		{
			int size;
			size = strlen(token)<=40 ? strlen(token): 41;
			*sha1sum = kzalloc(size, GFP_KERNEL);
			if(!*sha1sum) return -ENOMEM;
			memcpy(*sha1sum, token, size);
		}
		if(i == 2)
		{
			if(strlen(token) == 0)
			{
				suffix = NULL;
			}
			else
			{
				suffix = kzalloc(strlen(token)+1, GFP_KERNEL);
				if(!suffix) return -ENOMEM;
				memcpy(suffix, token, strlen(token));
			}
		}
		i++;
	}

	*filename = kzalloc(strlen(dest)+1, GFP_KERNEL);
	if(!*filename) return -ENOMEM;

	if(!prefix)
	{
		memcpy(*filename, dest, strlen(dest));
	}
	else
	{
		//printk(KERN_WARNING "CloudArmor: prefix is %s, %s, size is %d",prefix, dest+strlen(prefix), strlen(dest));
		memcpy(*filename, dest+strlen(prefix), strlen(dest)-strlen(prefix));
		kfree(prefix);
	}
	if(suffix)
	{
		int index = 0;
		index = strlen(*filename) - strlen(suffix);
		//printk(KERN_WARNING "CloudArmor: suffix is %s, index is %d",suffix, index);
		(*filename)[index] = '\0';
		kfree(suffix);
	}
	//printk(KERN_WARNING "CloudArmor: filename is %s, %x",*filename, filename);
	return 0;
}

static int calculate_file_digest(const char *name, char *digest)
{
	struct file *file;
	loff_t i_size, offset = 0;
	char *rbuf;
	unsigned char digest_bytes[20];
	int rc = 0;
	int j = 0;
	struct hash_desc desc;
	struct scatterlist sg[1];

	desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	desc.flags = 0;
	rc = crypto_hash_init(&desc);
	if(rc != 0) goto out;

	file = filp_open(name, O_LARGEFILE | O_RDONLY, MAY_OPEN);
	if (IS_ERR(file) || file==NULL)
	{
		rc = -EACCES;
		goto out;
	}

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!rbuf) {
		rc = -ENOMEM;
		filp_close(file, NULL);
		goto out;
	}

	i_size = i_size_read(file->f_dentry->d_inode);
	while(offset < i_size)
	{
		int rbuf_len;
		rbuf_len = kernel_read(file, offset, rbuf, PAGE_SIZE);
		if(rbuf_len < 0)
		{
			rc = rbuf_len;
			break;
		}
		if(rbuf_len == 0) break;
		offset += rbuf_len;

		sg_init_one(sg, rbuf, rbuf_len);
		rc = crypto_hash_update(&desc, sg, rbuf_len);
		if(rc) break;
	}
	kfree(rbuf);

	memset(digest, '\0', 41);
	if(!rc) rc = crypto_hash_final(&desc, digest_bytes);

	for(j=0; j<20; j++)
		sprintf(digest+2*j,"%02x",digest_bytes[j]);

	filp_close(file, NULL);
out:
	crypto_free_hash(desc.tfm);
	return rc;
}

static int state_transition()
{
	int tran_count, i,j;
	int flag = 0;
	unsigned char event_digest[20];


	// No policy set
	if(!policy_flag) return 0;

	printk(KERN_WARNING "CloudArmor: Event %d: %s", current_event->type, current_event->value);

	tran_count = states[current_state].tran_count;
	for(i=0; i<tran_count; i++)
	{
		//printk(KERN_WARNING "CloudArmor: Event is %s, type is %d",states[current_state].trans[i].event, current_event->type);

		if( current_event->type == TRAN_EXEC && strcmp(states[current_state].trans[i].event, current_event->value) == 0 )
		{
			// Check arguments
			struct pt_regs *reg;
			struct user_arg_ptr argv;
			int argc;
			char __user *const __user * __argv;
			int j = 0;
			int arg_flag = 1;
			// Get the execution arguments
			reg = task_pt_regs(current);
			if( !reg ) return -ENOMEM;
			// 64 bit, arguments saved in rdi, rsi, rdx, rcx, r8, r9
			__argv = (char __user *const __user *)reg->si;
			argv.ptr.native = __argv;
			argc = count(argv, MAX_ARG_STRINGS);

			// Check arguments
			for( j=0; j<states[current_state].trans[i].arg_count; j++)
			{
				char *event_arg;
				argument policy_arg;
				int arg_index = states[current_state].trans[i].args[j];

				policy_arg = arguments[arg_index];

				event_arg = (char *)get_user_arg_ptr(argv, policy_arg.index);
				if(!event_arg)
				{
					printk(KERN_WARNING "CloudArmor: Failed to retrieve %dth argument", i);
				}

				// Argument type is value, compare directly
				if( policy_arg.type == ARGU_VALUE && strncmp(event_arg, policy_arg.value, strlen(policy_arg.value)) != 0)
				{
					// Argument check failed!
					arg_flag = 0;
				}

				// Argument point to a file, check sha1sum of it
				if( policy_arg.type == ARGU_FILE )
				{
					char *filename;
					char *sha1sum;		// Standard value from policy
					char digest[41];	// Sha1 of target file
					int ret;

					//memset(digest, '\0', 41);
					ret = split_string("$", policy_arg.value, event_arg, &filename, &sha1sum);
					if(ret != 0) return ret;

					printk(KERN_WARNING "CloudArmor: filename is %s, policy(file_standard_hash) is %s", filename, sha1sum);

					// Get file sha1sum
					ret = calculate_file_digest(filename, digest);
					if(ret != 0)
					{
						// Something may have happened while calculating digest of file
						// Just use all 0s as the digest
					}

					printk(KERN_WARNING "CloudArmor: caculated file hash is %s",digest);

					if(strncmp(digest, sha1sum,40) != 0)
					{
						arg_flag = 0;
					}

					if(filename) kfree(filename);
					if(sha1sum) kfree(sha1sum);
				}


				printk(KERN_WARNING "CloudArmor: Checking Args %s vs. %s, len is %d", event_arg, policy_arg.value, strlen(policy_arg.value));
			}
			if( arg_flag )
			{
				// Transition
				printk(KERN_WARNING "CloudArmor: transition into state %d", states[current_state].trans[i].snum);
				flag = 1;
			}

		}

		if( flag == 0 && current_event->type == TRAN_PIPE && states[current_state].trans[i].transition_type == TRAN_PIPE )
		{
			// Sha1 of event value
			struct hash_desc desc;
			struct scatterlist sg;
			int len = strlen(current_event->value);
			char digest_x[40];

			memset(event_digest, 0, 20);
			sg_init_one(&sg, current_event->value, len);
			desc.tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

			crypto_hash_init(&desc);
			crypto_hash_update(&desc, &sg, len);
			crypto_hash_final(&desc, event_digest);

			crypto_free_hash(desc.tfm);

			memset(digest_x, 0,40);
			for(j=0; j<20; j++)
				sprintf(digest_x+2*j,"%02x",event_digest[j]);
			//printk(KERN_WARNING "CloudArmor: pipe write, sha1 is %s, is %s",digest_x);

			// Check event hash
			if(strncmp(digest_x, states[current_state].trans[i].event, 40) == 0 || strncmp(states[current_state].trans[i].event,"ANYTHING",0) == 0)
			{
				printk(KERN_WARNING "CloudArmor: transition into state %d", states[current_state].trans[i].snum);
				flag = 1;
			}
		}

		if(flag)
		{
			current_state = states[current_state].trans[i].snum;
			//if(current_state == state_count-1)
			if(strcmp(current_event->value, "/bin/date") == 0)
			{
				//model_state = STATE_FINISH;
				printk(KERN_WARNING "CloudArmor: FINISH STATE");
				current_state = 0;
				policy_flag = 0;
			}
			/*
			if(states[current_state].terminal_flag == 1)
			{
				model_state = STATE_FINISH;
				printk(KERN_WARNING "CloudArmor: FINISH STATE");
				// Re-initialize fsa
				current_state = 0;

				// For every run must put in a new policy?
				policy_flag = 0;
			}
			*/
			return 0;
		}
	}

	//model_state = STATE_ERROR;
	printk(KERN_WARNING "CloudArmor: State %d has no transition %s", current_state, current_event->value);
	printk(KERN_WARNING "CloudArmor: ERROR STATE");
	current_state = 0;
	policy_flag = 0;
	return 0;
}


static int cloudarmor_bprm_check_security(struct linux_binprm *bprm)
{
	task_security_struct *sec = current->cred->security;
	if( sec && sec->child_flag == 1 && sec->parent_flag == 0)
	{
		struct pt_regs *reg;
		char *filename;
		struct user_arg_ptr argv;
		int argc;
		char __user *const __user * __argv;
		int i = 0;
		int nsize;
		int ret;
		//printk(KERN_WARNING "CloudArmor: Executable %s(%s) executed PID(%d), parent(%d)\n", bprm->filename, bprm->interp, current->pid, current->real_parent->pid);
		// Get the execution arguments
		reg = task_pt_regs(current);
		if( !reg ) return -ENOMEM;
		// 64 bit, arguments saved in rdi, rsi, rdx, rcx, r8, r9
		//filename = (char *)reg->di;
		//printk(KERN_WARNING "CloudArmor: test filename %s, %d, %d, %d",filename, reg->di, reg->si,reg->dx);
		__argv = (char __user *const __user *)reg->si;
		//argv = { .ptr.native = __argv };
		argv.ptr.native = __argv;
		argc = count(argv, MAX_ARG_STRINGS);

		if(strcmp("/bin/echo", bprm->filename) == 0)
		{
			//Mark start of event
			//model_state = STATE_ONGOING;
			echo_flag = 1;
			char __user *str;
			getnstimeofday(&ts);
			str = get_user_arg_ptr(argv, 1);
			printk(KERN_WARNING "CloudArmorLog: ------------------------%s---------------------------------", (char *)str);
			return 0;
		}


		// Things we want to purge from the execution
		if(strcmp("/usr/bin/env", bprm->filename) == 0 || strstr(bprm->filename, "dump_policy") !=  NULL)
		{
			return 0;
		}

		if(echo_flag)
		{
			char __user *str;
			str = get_user_arg_ptr(argv, 1);
			printk(KERN_WARNING "CloudArmorLog: %s %d", bprm->filename, ts.tv_sec);
		}
		/*
		// Print out all arguments
		printk("CloudArmor: ");
		while ( i < argc ){
			char __user *str;
			str = get_user_arg_ptr(argv, i);
			printk("%s ",(char *)str);
			i++;
		}
		printk("\n");
		*/
		if(strcmp(bprm->filename, "/usr/bin/tee") == 0)
			tee_flag = 1;
		else
			tee_flag = 0;

		if(strcmp(bprm->filename, "/sbin/iptables-save") == 0)
			iptsave_flag = 1;
		else
			iptsave_flag = 0;

		if(strcmp(bprm->filename, "/sbin/iptables-restore") == 0)
			iptrestore_flag = 1;
		else
			iptrestore_flag = 0;

		if(current_event) kfree(current_event);

		current_event = kmalloc(sizeof(event), GFP_KERNEL);
		if(!current_event) return -ENOMEM;

		memset(current_event, 0, sizeof(event));

		/*
		// Set event structure accordingly
		nsize = (strlen(bprm->filename) < NAME_SIZE) ? strlen(bprm->filename): NAME_SIZE;
		memcpy(current_event->name, bprm->filename, nsize);
		*/
		//printk(KERN_WARNING "event is %s, bprm event is %s, size is %d, bprmsize is %d, namesize is %d", current_event->name, bprm->filename, nsize, strlen(bprm->filename), NAME_SIZE);

		current_event->value = bprm->filename;
		current_event->size = strlen(bprm->filename);
		current_event->type = TRAN_EXEC;

		ret = state_transition();

		if(strcmp("/bin/date", bprm->filename) == 0)
		{
			/*
			if(model_state == STATE_ONGOING)
			{
				model_state = STATE_ERROR;
				//printk(KERN_WARNING "CloudArmor: ERROR STATE");
			}
			*/
			printk(KERN_WARNING "CloudArmorLog: --------------------------------END-----------------------------------------");
			echo_flag = 0;
			tee_flag = 0;
			iptsave_flag = 0;
			iptrestore_flag = 0;
		}
		return ret;
	}
	return 0;
}


static int cloudarmor_bprm_set_creds(struct linux_binprm *bprm)
{
	task_security_struct *sec = NULL;
	task_security_struct *new = NULL;
	//struct cred *new_cred =  NULL;
	int rc = 0;

	int error = cap_bprm_set_creds(bprm);
	if(error) return error;

	if (bprm->cred_prepared) return 0;

	//printk(KERN_WARNING "CloudArmor:%s is running",bprm->filename);
	if(strcmp(bprm->filename, "/usr/bin/nova-compute") == 0 || strcmp(bprm->filename, "/root/testme.py") == 0)
	{
		current_state = 0;
		printk(KERN_WARNING "CloudArmor:nova-compute PID: %d is running", current->pid);
		sec = kmalloc(sizeof(task_security_struct),GFP_KERNEL);
		if( !sec ) return -ENOMEM;
		sec->parent_flag = 1;
		sec->child_flag = 0;
		//new_cred = prepare_creds();
		//if(!new_cred) return -ENOMEM;

		//new_cred->security = sec;
		//commit_creds(new_cred);
		bprm->cred->security = sec;
		echo_flag = 0;
		return 0;
	}
	return 0;
}

static int cloudarmor_bprm_committed_creds(struct linux_binprm *bprm)
{
	//printk(KERN_WARNING "Cloudarmor: %s security of current is %x, %x", bprm->filename, current->cred->security, current->real_cred->security);
	return 0;
}

static int cloudarmor_task_create(unsigned long clone_flags)
{
	return 0;
}

static int cloudarmor_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	task_security_struct *sec  = kmalloc(sizeof(task_security_struct),GFP_KERNEL);
	if(!sec) return -ENOMEM;

	cred->security = sec;
	return 0;
}

static void cloudarmor_cred_free(struct cred *cred)
{
	task_security_struct *sec = cred->security;
	cred->security = NULL;
	kfree(sec);
}


static int cloudarmor_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	task_security_struct *old_sec = old->security;
	task_security_struct *new_sec = NULL;
	int rc = 0;


	if( !old_sec ) return 0;

	//printk(KERN_WARNING "Cloudarmor: pid is %d, %x, %x",current->pid, current->cred->security, current->real_cred->security);
	new_sec = kmalloc(sizeof(task_security_struct),GFP_KERNEL);
	if(!new_sec) return -ENOMEM;

	rc = tss_copy(old_sec, new_sec);
	if(rc != 0) return rc;

	if( new_sec->parent_flag == 1 )
	{
		new_sec->parent_flag = 0;
		new_sec->child_flag = 1;
	}
	else
	{
		new_sec->parent_flag = 1;
		new_sec->child_flag = 0;
	}

	new->security = new_sec;
	return 0;
}

static void cloudarmor_cred_transfer(struct cred *new, const struct cred *old)
{
	task_security_struct *old_sec = old->security;
	task_security_struct *new_sec = new->security;
}


static int cloudarmor_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	//printk(KERN_WARNING "CloudArmor: socket connect address is %s", address->sa_data);
	socket_security_struct *sec = sock->sk->sk_security;

	if( strcmp(address->sa_data,"/var/run/libvirt/libvirt-sock") == 0 )
	{
		//printk(KERN_WARNING "CloudArmor: connecting to libvirt");
		if(!sec)
		{
			sec = kmalloc(sizeof(socket_security_struct),GFP_KERNEL);
			if(!sec) return -ENOMEM;

			sec->libvirt_flag = 1;
			sock->sk->sk_security = sec;
		}
		else
		{
			sec->libvirt_flag = 1;
		}
	}
	return 0;
}

static int cloudarmor_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	socket_security_struct *sec = sock->sk->sk_security;

	if( !sec ) return 0;

	if( sec->libvirt_flag == 1 )
	{
		//print_buffer((char __user *)msg->msg_iov->iov_base, size, 1);
		//printk(KERN_WARNING "CloudArmor: libvirt write, msg length is %d", size);
		//printk(KERN_WARNING "CloudArmor: libvirt write, msg is %s",(char __user *)msg->msg_iov->iov_base);
	}

	return 0;
}

static int cloudarmor_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags)
{

	socket_security_struct *sec = sock->sk->sk_security;
	struct sk_buff *skb;
	int err;

	if( !sec ) return 0;

	if( sec->libvirt_flag == 1 )
	{
		//print_buffer((char __user *)msg->msg_iov->iov_base, size, 0);
		//printk(KERN_WARNING "CloudArmor: libvirt read, msg length is %d", size);
		//printk(KERN_WARNING "CloudArmor: libvirt read, msg is %s",(char __user *)msg->msg_iov->iov_base);
	}
	return 0;
}

static int cloudarmor_pipe_write(struct file *filp, struct iovec *iov, int size, unsigned long nr_segs)
{
	//printk(KERN_WARNING "CloudArmor: pipe write");
	task_security_struct *sec = current->cred->security;
	pipe_security_struct *pipe_sec = filp->f_security;
	int err;
	if( pipe_sec && (tee_flag || iptrestore_flag || iptsave_flag))
	{

		char * show = kmalloc(size+1, GFP_KERNEL);
		if(!show)
			return ENOMEM;
		err = cloudarmor_copy_from_user(show, iov, size, nr_segs);
		show[size] = '\0';
		if(err)
			return err;
		//printk(KERN_WARNING "CloudArmor: PIPEwrite (PID %d, len %d): %s\n", current->pid, size, show);

		if(tee_flag == 1)
			tee_flag = 0;
		else if(iptrestore_flag == 1)
			iptrestore_flag = 0;
		else
			iptsave_flag = 0;


                if(current_event) kfree(current_event);

                current_event = kmalloc(sizeof(event), GFP_KERNEL);
                if(!current_event) return -ENOMEM;

                memset(current_event, 0, sizeof(event));
                // Set event structure accordingly
		current_event->value = show;
		current_event->size = size;
		current_event->type = TRAN_PIPE;

		state_transition();

		kfree(show);
	}
	return 0;
}

static int cloudarmor_pipe_read(struct file *filp, struct iovec * iov, int size)
{
	return 0;
}

static int cloudarmor_pipe_create(struct file *f, int flag)
{
	task_security_struct *sec = current->cred->security;
	if( sec && sec->parent_flag == 1)
	{
		pipe_security_struct * pipe_sec = kmalloc(sizeof(pipe_security_struct), GFP_KERNEL);
		if(!pipe_sec)
			return ENOMEM;

		pipe_sec->pipe_flag = flag;

		if(f->f_security)
		{
			printk(KERN_WARNING "CloudArmor: ERROR pipe already has security field");
			kfree(pipe_sec);
			return 0;
		}

		f->f_security = pipe_sec;
	}
	return 0;
}

static void cloudarmor_file_free_security(struct file *f)
{
	if(f->f_security)
	{
		kfree(f->f_security);
		f->f_security = NULL;
	}
}


static struct security_operations cloudarmor_ops = {
	.bprm_check_security = 		cloudarmor_bprm_check_security,
	.bprm_set_creds =   		cloudarmor_bprm_set_creds,
	.bprm_committed_creds = 	cloudarmor_bprm_committed_creds,
	.task_create =         		cloudarmor_task_create,
	//.cred_alloc_blank =		cloudarmor_cred_alloc_blank,
	//.cred_free =			cloudarmor_cred_free,
	.cred_prepare =			cloudarmor_cred_prepare,
	//.cred_transfer =		cloudarmor_cred_transfer,

	.socket_connect =		cloudarmor_socket_connect,
	.socket_sendmsg =		cloudarmor_socket_sendmsg,
	.socket_recvmsg =		cloudarmor_socket_recvmsg,

	.pipe_create = 			cloudarmor_pipe_create,
	.pipe_write =			cloudarmor_pipe_write,
	.pipe_read = 			cloudarmor_pipe_read,

	.file_free_security =           cloudarmor_file_free_security,
#if 0
	.inode_permission =		sample_inode_permission,
	.bprm_set_security =		sample_bprm_set_security,
	.inode_init_security =		sample_inode_init_security,
	.ptrace_access_check =		selinux_ptrace_access_check,
	.ptrace_traceme =		selinux_ptrace_traceme,
	.capget =			selinux_capget,
	.capset =			selinux_capset,
	.sysctl =			selinux_sysctl,
	.capable =			selinux_capable,
	.quotactl =			selinux_quotactl,
	.quota_on =			selinux_quota_on,
	.syslog =			selinux_syslog,
	.vm_enough_memory =		selinux_vm_enough_memory,

	.netlink_send =			selinux_netlink_send,
	.netlink_recv =			selinux_netlink_recv,

	.bprm_set_creds =		selinux_bprm_set_creds,
	.bprm_committing_creds =	selinux_bprm_committing_creds,
	.bprm_committed_creds =		selinux_bprm_committed_creds,
	.bprm_secureexec =		selinux_bprm_secureexec,

	.sb_alloc_security =		selinux_sb_alloc_security,
	.sb_free_security =		selinux_sb_free_security,
	.sb_copy_data =			selinux_sb_copy_data,
	.sb_kern_mount =		selinux_sb_kern_mount,
	.sb_show_options =		selinux_sb_show_options,
	.sb_statfs =			selinux_sb_statfs,
	.sb_mount =			selinux_mount,
	.sb_umount =			selinux_umount,
	.sb_set_mnt_opts =		selinux_set_mnt_opts,
	.sb_clone_mnt_opts =		selinux_sb_clone_mnt_opts,
	.sb_parse_opts_str = 		selinux_parse_opts_str,


	.inode_alloc_security =		selinux_inode_alloc_security,
	.inode_free_security =		selinux_inode_free_security,
	.inode_init_security =		selinux_inode_init_security,
	.inode_create =			selinux_inode_create,
	.inode_link =			selinux_inode_link,
	.inode_unlink =			selinux_inode_unlink,
	.inode_symlink =		selinux_inode_symlink,
	.inode_mkdir =			selinux_inode_mkdir,
	.inode_rmdir =			selinux_inode_rmdir,
	.inode_mknod =			selinux_inode_mknod,
	.inode_rename =			selinux_inode_rename,
	.inode_readlink =		selinux_inode_readlink,
	.inode_follow_link =		selinux_inode_follow_link,
	.inode_permission =		selinux_inode_permission,
	.inode_setattr =		selinux_inode_setattr,
	.inode_getattr =		selinux_inode_getattr,
	.inode_setxattr =		selinux_inode_setxattr,
	.inode_post_setxattr =		selinux_inode_post_setxattr,
	.inode_getxattr =		selinux_inode_getxattr,
	.inode_listxattr =		selinux_inode_listxattr,
	.inode_removexattr =		selinux_inode_removexattr,
	.inode_getsecurity =		selinux_inode_getsecurity,
	.inode_setsecurity =		selinux_inode_setsecurity,
	.inode_listsecurity =		selinux_inode_listsecurity,
	.inode_getsecid =		selinux_inode_getsecid,

	.file_permission =		selinux_file_permission,
	.file_alloc_security =		selinux_file_alloc_security,
	.file_free_security =		selinux_file_free_security,
	.file_ioctl =			selinux_file_ioctl,
	.file_mmap =			selinux_file_mmap,
	.file_mprotect =		selinux_file_mprotect,
	.file_lock =			selinux_file_lock,
	.file_fcntl =			selinux_file_fcntl,
	.file_set_fowner =		selinux_file_set_fowner,
	.file_send_sigiotask =		selinux_file_send_sigiotask,
	.file_receive =			selinux_file_receive,

	.dentry_open =			selinux_dentry_open,

	.task_create =			selinux_task_create,
	.cred_alloc_blank =		selinux_cred_alloc_blank,
	.cred_free =			selinux_cred_free,
	.cred_prepare =			selinux_cred_prepare,
	.cred_transfer =		selinux_cred_transfer,
	.kernel_act_as =		selinux_kernel_act_as,
	.kernel_create_files_as =	selinux_kernel_create_files_as,
	.kernel_module_request =	selinux_kernel_module_request,
	.task_setpgid =			selinux_task_setpgid,
	.task_getpgid =			selinux_task_getpgid,
	.task_getsid =			selinux_task_getsid,
	.task_getsecid =		selinux_task_getsecid,
	.task_setnice =			selinux_task_setnice,
	.task_setioprio =		selinux_task_setioprio,
	.task_getioprio =		selinux_task_getioprio,
	.task_setrlimit =		selinux_task_setrlimit,
	.task_setscheduler =		selinux_task_setscheduler,
	.task_getscheduler =		selinux_task_getscheduler,
	.task_movememory =		selinux_task_movememory,
	.task_kill =			selinux_task_kill,
	.task_wait =			selinux_task_wait,
	.task_to_inode =		selinux_task_to_inode,

	.ipc_permission =		selinux_ipc_permission,
	.ipc_getsecid =			selinux_ipc_getsecid,

	.msg_msg_alloc_security =	selinux_msg_msg_alloc_security,
	.msg_msg_free_security =	selinux_msg_msg_free_security,

	.msg_queue_alloc_security =	selinux_msg_queue_alloc_security,
	.msg_queue_free_security =	selinux_msg_queue_free_security,
	.msg_queue_associate =		selinux_msg_queue_associate,
	.msg_queue_msgctl =		selinux_msg_queue_msgctl,
	.msg_queue_msgsnd =		selinux_msg_queue_msgsnd,
	.msg_queue_msgrcv =		selinux_msg_queue_msgrcv,

	.shm_alloc_security =		selinux_shm_alloc_security,
	.shm_free_security =		selinux_shm_free_security,
	.shm_associate =		selinux_shm_associate,
	.shm_shmctl =			selinux_shm_shmctl,
	.shm_shmat =			selinux_shm_shmat,

	.sem_alloc_security =		selinux_sem_alloc_security,
	.sem_free_security =		selinux_sem_free_security,
	.sem_associate =		selinux_sem_associate,
	.sem_semctl =			selinux_sem_semctl,
	.sem_semop =			selinux_sem_semop,

	.d_instantiate =		selinux_d_instantiate,

	.getprocattr =			selinux_getprocattr,
	.setprocattr =			selinux_setprocattr,

	.secid_to_secctx =		selinux_secid_to_secctx,
	.secctx_to_secid =		selinux_secctx_to_secid,
	.release_secctx =		selinux_release_secctx,
	.inode_notifysecctx =		selinux_inode_notifysecctx,
	.inode_setsecctx =		selinux_inode_setsecctx,
	.inode_getsecctx =		selinux_inode_getsecctx,

	.unix_stream_connect =		selinux_socket_unix_stream_connect,
	.unix_may_send =		selinux_socket_unix_may_send,

	.socket_create =		selinux_socket_create,
	.socket_post_create =		selinux_socket_post_create,
	.socket_bind =			selinux_socket_bind,
	.socket_connect =		selinux_socket_connect,
	.socket_listen =		selinux_socket_listen,
	.socket_accept =		selinux_socket_accept,
	.socket_sendmsg =		selinux_socket_sendmsg,
	.socket_recvmsg =		selinux_socket_recvmsg,
	.socket_getsockname =		selinux_socket_getsockname,
	.socket_getpeername =		selinux_socket_getpeername,
	.socket_getsockopt =		selinux_socket_getsockopt,
	.socket_setsockopt =		selinux_socket_setsockopt,
	.socket_shutdown =		selinux_socket_shutdown,
	.socket_sock_rcv_skb =		selinux_socket_sock_rcv_skb,
	.socket_getpeersec_stream =	selinux_socket_getpeersec_stream,
	.socket_getpeersec_dgram =	selinux_socket_getpeersec_dgram,
	.sk_alloc_security =		selinux_sk_alloc_security,
	.sk_free_security =		selinux_sk_free_security,
	.sk_clone_security =		selinux_sk_clone_security,
	.sk_getsecid =			selinux_sk_getsecid,
	.sock_graft =			selinux_sock_graft,
	.inet_conn_request =		selinux_inet_conn_request,
	.inet_csk_clone =		selinux_inet_csk_clone,
	.inet_conn_established =	selinux_inet_conn_established,
	.req_classify_flow =		selinux_req_classify_flow,
	.tun_dev_create =		selinux_tun_dev_create,
	.tun_dev_post_create = 		selinux_tun_dev_post_create,
	.tun_dev_attach =		selinux_tun_dev_attach,

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	.xfrm_policy_alloc_security =	selinux_xfrm_policy_alloc,
	.xfrm_policy_clone_security =	selinux_xfrm_policy_clone,
	.xfrm_policy_free_security =	selinux_xfrm_policy_free,
	.xfrm_policy_delete_security =	selinux_xfrm_policy_delete,
	.xfrm_state_alloc_security =	selinux_xfrm_state_alloc,
	.xfrm_state_free_security =	selinux_xfrm_state_free,
	.xfrm_state_delete_security =	selinux_xfrm_state_delete,
	.xfrm_policy_lookup =		selinux_xfrm_policy_lookup,
	.xfrm_state_pol_flow_match =	selinux_xfrm_state_pol_flow_match,
	.xfrm_decode_session =		selinux_xfrm_decode_session,
#endif

#ifdef CONFIG_KEYS
	.key_alloc =			selinux_key_alloc,
	.key_free =			selinux_key_free,
	.key_permission =		selinux_key_permission,
	.key_getsecurity =		selinux_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
	.audit_rule_init =		selinux_audit_rule_init,
	.audit_rule_known =		selinux_audit_rule_known,
	.audit_rule_match =		selinux_audit_rule_match,
	.audit_rule_free =		selinux_audit_rule_free,
#endif

#endif /* sample if 0 */
};


static __init int cloudarmor_init(void)
{

	if (register_security (&cloudarmor_ops)) {
		printk("CloudArmor: Unable to register with kernel.\n");
		return 0;
	}
	printk(KERN_INFO "CloudArmor:  Initializing.\n");
	return 0;
}

static __exit void cloudarmor_exit(void)
{
	printk(KERN_INFO "CloudArmor: Exiting.\n");
	//unregister_security(&cloudarmor_ops);
	//debugfs_remove_recursive(dirret);
}

security_initcall(cloudarmor_init);
