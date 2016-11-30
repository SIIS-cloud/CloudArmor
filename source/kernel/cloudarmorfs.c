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
//#include <linux/module.h>
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
#include "ndfsa.h"

struct dentry *dirret,*fileret ;
int filevalue;

state *states;
int state_count;
int current_state;
int policy_flag;
int arg_count;
argument *arguments;
int file_flag;
int start_flag;
int policy_len;
int current_len;
unsigned char *policy_buf;

static void init_fsa(unsigned char *kern_buf, int count)
{
	state *st;
	argument *arg;
	int i;

	state_count = *((int *)kern_buf);
	kern_buf += sizeof(int);
	st = (state *)kern_buf;
	printk(KERN_WARNING "CloudArmor: there are %d states\n",state_count);

	for(i=0; i<state_count; i++)
		printk(KERN_WARNING "CloudArmor: state is %d, have %d transitions, transition %s\n", st[i].snum, st[i].tran_count, st[i].trans[0].event);

	if(states) kfree(states);

	states = kzalloc(sizeof(state)*state_count, GFP_NOFS);
	if(!states) return -ENOMEM;

	memcpy(states, st, sizeof(state)*state_count);

	kern_buf += sizeof(state)*state_count;
	arg_count = *((int *)kern_buf);
	kern_buf += sizeof(int);

	if(arguments) kfree(arguments);
	printk(KERN_WARNING "CloudArmor: arg_count is %d",arg_count);
	if(arg_count != 0)
	{
		arg = (argument *)kern_buf;
		for(i=0; i<arg_count; i++)
			printk(KERN_WARNING "CloudArmor: argument %d is %s", i, arg[i].value);


		arguments = kzalloc(sizeof(argument)*arg_count, GFP_NOFS);
		if(!arguments && arg_count!=0) return -ENOMEM;

		memcpy(arguments, kern_buf, sizeof(argument)*arg_count);
	}
	else
	{
		printk(KERN_WARNING "CloudArmor: No arguments specified");
	}

	policy_flag = 1;
}

static ssize_t load_policy_binary(struct file *fp, const char __user *user_buffer,size_t count, loff_t *position)
{
	int error;
	unsigned char *kern_buf = kzalloc(count, GFP_NOFS);
	//char *tmp;

	if(!kern_buf) return -ENOMEM;

	memset(kern_buf, 0, count);


	//tmp = (char *)__get_free_page(GFP_TEMPORARY);
	//if(!tmp) return ENOMEM;
	if(copy_from_user(kern_buf, user_buffer, count))
	{
		error = -EFAULT;
		if(kern_buf) kfree(kern_buf);
		return error;
	}

	if(kern_buf[0] == '#' && count == 1)
	{
		// Begin accepting new policy
		if(kern_buf) kfree(kern_buf);
		file_flag = 0;
		current_len = 0;
		start_flag = 1;
		if(policy_buf) kfree(policy_buf);

		return count;
	}

	if(file_flag == 0 && start_flag == 1)
	{
		// Policy length
		policy_len = *((int *)kern_buf);
		file_flag = 1;
		policy_buf = kzalloc(policy_len, GFP_NOFS);
		if(!policy_buf) return -ENOMEM;
		printk(KERN_WARNING "CloudArmor: policy length is %d",policy_len);
		if(kern_buf) kfree(kern_buf);
		return count;
	}

	if(file_flag == 1 && start_flag == 1)
	{
		memcpy(policy_buf+current_len, kern_buf, count);
		current_len += count;
		printk(KERN_WARNING "CloudArmor: Copying policy from userspace to the kernel");
	}

	if(current_len == policy_len && start_flag == 1)
	{
		printk(KERN_WARNING "CloudArmor: Initializing the FSA");
		init_fsa(policy_buf, policy_len);
		start_flag = 0;
	}

	if(kern_buf) kfree(kern_buf);

	return count;
}

static const struct file_operations fops_security = {
        //.read = myreader,
        .write = load_policy_binary,
	//.read = read_policy_binary,
};

static __init int cloudarmorfs_init(void)
{
	policy_flag = 0;
	start_flag = 0;
	current_len = 0;
	dirret = securityfs_create_dir("cloudarmor", NULL);
	fileret = securityfs_create_file("policy", 0644, dirret, &filevalue, &fops_security);
	//whitelist = securityfs_create_file("white_list", 0644, dirret, &filevalue2, &fops_security);
	file_flag = 0;
	printk(KERN_INFO "CloudArmorFS:  Done.\n");
	return 0;
}

fs_initcall(cloudarmorfs_init);
