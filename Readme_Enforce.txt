Installing Logging infrastructure

1. download kernel patch 

	https://siissvn.cse.psu.edu/svn/src/cloud10/cloudarmor/patch/patch.cloudenforce.2.19

2. apply kernel patch. (You need a clean linux-3.2.1 kernel in this step. DO NOT use the one for logging)
	enter your kernel source directory, in our case linux-3.2.1
	cd linux-3.2.1
	patch -p1 < ../patch.enforce.2.19

3. compile kernel.
	On VM host & within VM (If you already have kernel compiled within the VM, you only need to compile it on the host)
		make -j32
		make modules_install
		make install

4. modify VM configuration to boot from our kernel.
	In virt-manager, details->Boot Options->Direct Kernel boot,
	Specify kernel path to be  /boot/vmlinuz-3.2.1
	Specify initrd path to be  /boot/initrd.img-3.2.1
	Specify kernel arguments to be root=UUID=e5ab03ee-032f-449f-b8e1-db4405e41e8f ro security=cloudarmor
	(*Note: ) root=UUID=$, $should be your own root file system UUID. You can find it out by checking file /boot/grub/grub.cfg within your VM.
	In virt-manager, apply the changes

5. reboot VM.
	start eth1 
		ifconfig eth1 up

6. Enforcing
	Download policy generation tools
		
		https://siissvn.cse.psu.edu/svn/src/cloud10/cloudarmor/policy/	

	Compile policy
		gcc dump_policy.c -o dump_policy (binary dump_policy will be used by nova-compute to dump policy into the kernel)
		python policygen.py (This step requires the graph file from Synptoic tool, the output is the policy.c file)
		gcc policy.c -o policy  
		./policy	(This step generates the binary policy file. The output is policy_structs)
		cp policy_structs METHOD_policy (You shuold change METHOD accordingly, for example, run_instance_policy is the policy file for run_instance method)


	Place all the files under /root/policies directory, nova-compute will try to find policy under this specific directory

7. Apply openstack Patch
	
	Download it at https://siissvn.cse.psu.edu/svn/src/cloud10/cloudarmor/source/openstack/amqp.py

	cp amqp.py /usr/lib/python2.7/dist-packages/nova/openstack/common/rpc/amqp.py

8. Start nova-compute
	nova-compute

9. Beging Enforcing

	To see kernel logs
		dmesg

	CloudArmor log will be started by "CloudArmor:"
	Commands executed by nova-compute will be started by "CloudArmorLog:"

	If nova-compute behaves in a way as specified by the model, it will enter "FINISH STATE". Otherwise, it will enter "ERROR STATE"
	A sample log is shown below:

[ 3889.827892] CloudArmor: Copying policy from userspace to the kernel
[ 3889.828767] CloudArmor: Copying policy from userspace to the kernel
[ 3889.829556] CloudArmor: Copying policy from userspace to the kernel
[ 3889.830377] CloudArmor: Initializing the FSA
[ 3889.831082] CloudArmor: there are 28 states
[ 3889.832115] CloudArmor: state is 0, have 1 transitions, transition /usr/bin/qemu-img
[ 3889.833117] CloudArmor: state is 1, have 1 transitions, transition /bin/readlink
[ 3889.834104] CloudArmor: state is 2, have 1 transitions, transition /bin/readlink
[ 3889.835106] CloudArmor: state is 3, have 1 transitions, transition /bin/readlink
[ 3889.836155] CloudArmor: state is 4, have 1 transitions, transition /bin/readlink
[ 3889.838692] CloudArmor: state is 5, have 1 transitions, transition /bin/chmod
[ 3889.839398] CloudArmor: state is 6, have 1 transitions, transition /bin/chown
[ 3889.840157] CloudArmor: state is 7, have 1 transitions, transition /bin/mkdir
[ 3889.840858] CloudArmor: state is 8, have 2 transitions, transition /bin/chmod
[ 3889.841559] CloudArmor: state is 9, have 2 transitions, transition /bin/readlink
[ 3889.842560] CloudArmor: state is 10, have 1 transitions, transition /sbin/kpartx
[ 3889.843564] CloudArmor: state is 11, have 1 transitions, transition /sbin/ip
[ 3889.844312] CloudArmor: state is 12, have 1 transitions, transition /sbin/resize2fs
[ 3889.845325] CloudArmor: state is 13, have 1 transitions, transition /sbin/brctl
[ 3889.846305] CloudArmor: state is 14, have 2 transitions, transition /sbin/ip
[ 3889.847018] CloudArmor: state is 15, have 1 transitions, transition ANYTHING
[ 3889.847705] CloudArmor: state is 16, have 1 transitions, transition ANYTHING
[ 3889.848454] CloudArmor: state is 17, have 2 transitions, transition /bin/mount
[ 3889.849435] CloudArmor: state is 18, have 2 transitions, transition /sbin/ip
[ 3889.850124] CloudArmor: state is 19, have 4 transitions, transition /sbin/e2fsck
[ 3889.851137] CloudArmor: state is 20, have 2 transitions, transition /sbin/ip
[ 3889.851841] CloudArmor: state is 21, have 1 transitions, transition ANYTHING
[ 3889.852589] CloudArmor: state is 22, have 1 transitions, transition ANYTHING
[ 3889.853286] CloudArmor: state is 23, have 1 transitions, transition /bin/readlink
[ 3889.854277] CloudArmor: state is 24, have 1 transitions, transition /usr/bin/tee
[ 3889.855293] CloudArmor: state is 25, have 1 transitions, transition /sbin/iptables-restore
[ 3889.856391] CloudArmor: state is 26, have 1 transitions, transition /bin/readlink
[ 3889.857398] CloudArmor: state is 27, have 1 transitions, transition /usr/bin/qemu-img
[ 3889.858445] CloudArmor: arg_count is 0
[ 3889.858726] CloudArmor: No arguments specified
[ 3889.890760] CloudArmorLog: ------------------------run_instance---------------------------------
[ 3892.904186] CloudArmorLog: /usr/bin/qemu-img 1392842926
[ 3892.904957] CloudArmor: Event 0: /usr/bin/qemu-img
[ 3892.905671] CloudArmor: transition into state 19
[ 3893.052399] CloudArmorLog: /usr/bin/qemu-nbd 1392842926
[ 3893.053166] CloudArmor: Event 0: /usr/bin/qemu-nbd
[ 3893.053876] CloudArmor: transition into state 20
[ 3893.133620] CloudArmorLog: /sbin/kpartx 1392842926
[ 3893.134405] CloudArmor: Event 0: /sbin/kpartx
[ 3893.135119] CloudArmor: transition into state 17
[ 3893.165379] CloudArmorLog: /bin/mount 1392842926
[ 3893.166130] CloudArmor: Event 0: /bin/mount
[ 3893.166845] CloudArmor: transition into state 4
[ 3893.236570] EXT4-fs (dm-0): mounted filesystem with ordered data mode. Opts: (null)
[ 3893.280875] CloudArmorLog: /bin/readlink 1392842926
[ 3893.281249] CloudArmor: Event 0: /bin/readlink
[ 3893.281963] CloudArmor: transition into state 7
[ 3893.319792] CloudArmorLog: /bin/mkdir 1392842926
[ 3893.320614] CloudArmor: Event 0: /bin/mkdir
[ 3893.321303] CloudArmor: transition into state 3
[ 3893.364078] CloudArmorLog: /bin/readlink 1392842926
[ 3893.364827] CloudArmor: Event 0: /bin/readlink
[ 3893.365521] CloudArmor: transition into state 6
[ 3893.387485] CloudArmorLog: /bin/chown 1392842926
[ 3893.398590] CloudArmor: Event 0: /bin/chown
[ 3893.399346] CloudArmor: transition into state 2
[ 3893.425701] CloudArmorLog: /bin/readlink 1392842926
[ 3893.426447] CloudArmor: Event 0: /bin/readlink
[ 3893.427157] CloudArmor: transition into state 8
[ 3893.462354] CloudArmorLog: /bin/chmod 1392842926
[ 3893.463122] CloudArmor: Event 0: /bin/chmod
[ 3893.463807] CloudArmor: transition into state 23
[ 3893.502050] CloudArmorLog: /bin/readlink 1392842926
[ 3893.502827] CloudArmor: Event 0: /bin/readlink
[ 3893.503527] CloudArmor: transition into state 8
[ 3893.537479] CloudArmorLog: /usr/bin/tee 1392842926
[ 3893.538234] CloudArmor: Event 0: /usr/bin/tee
[ 3893.538951] CloudArmor: transition into state 21
[ 3893.545242] CloudArmor: Event 1: |# The following ssh key was injected by Nova|ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGvmxJBHy+4QJF0Sfy1A4eq7OONG8IaO+rxylIdpc7C6Ja7OyieYE6KT4mKfzKqEFLhGGQfuUZHkp6I2vM7W2IeBMVCaCGWpTnLFlHL0/hFs1K2KPFRQUqklkfVjUoEW2MSGgxQLSMtm3IqFCSLvlkKxUzcoIUoVvE+Yy135K6L3gW+++Y2mWWQMdQeLOtsld1M4zv5/uxYaoVkzyVxxzXI8fyaZ0i/K4jJs2p5q2TnH9EAFqheWazk+9otOIp/eBnb4tguN6NUhrT5oXQcRlnqfZnhrEv2Xf2nKbSlkh4HgXHhCi0RPg3eDgPvdNkpbjufYYG9Q4h284DPmoRBR7J Generated by Nova|
[ 3893.549377] CloudArmor: transition into state 26
[ 3893.582916] CloudArmorLog: /bin/readlink 1392842926
[ 3893.583729] CloudArmor: Event 0: /bin/readlink
[ 3893.584549] CloudArmor: transition into state 5
[ 3893.621265] CloudArmorLog: /bin/chmod 1392842926
[ 3893.622011] CloudArmor: Event 0: /bin/chmod
[ 3893.622706] CloudArmor: transition into state 1
[ 3893.647125] CloudArmorLog: /bin/readlink 1392842926
[ 3893.658506] CloudArmor: Event 0: /bin/readlink
[ 3893.659231] CloudArmor: transition into state 9
[ 3893.679209] CloudArmorLog: /bin/readlink 1392842926
[ 3893.679957] CloudArmor: Event 0: /bin/readlink
[ 3893.680706] CloudArmor: transition into state 9
[ 3893.716650] CloudArmorLog: /bin/umount 1392842926
[ 3893.717393] CloudArmor: Event 0: /bin/umount
[ 3893.718079] CloudArmor: transition into state 10
[ 3893.880171] CloudArmorLog: /sbin/kpartx 1392842926
[ 3893.880919] CloudArmor: Event 0: /sbin/kpartx
[ 3893.881611] CloudArmor: transition into state 17
[ 3893.906023] CloudArmorLog: /usr/bin/qemu-nbd 1392842926
[ 3893.906808] CloudArmor: Event 0: /usr/bin/qemu-nbd
[ 3893.907518] CloudArmor: transition into state 20
[ 3893.923538] block nbd10: NBD_DISCONNECT
[ 3893.924768] block nbd10: Receive control failed (result -32)
[ 3893.925543] block nbd10: queue cleared
[ 3894.654494] CloudArmorLog: /sbin/ip 1392842926
[ 3894.654858] CloudArmor: Event 0: /sbin/ip
[ 3894.655544] CloudArmor: transition into state 13
[ 3894.704614] CloudArmorLog: /sbin/brctl 1392842926
[ 3894.705366] CloudArmor: Event 0: /sbin/brctl
[ 3894.706057] CloudArmor: transition into state 11
[ 3894.727926] CloudArmorLog: /sbin/ip 1392842926
[ 3894.739932] CloudArmor: Event 0: /sbin/ip
[ 3894.740667] CloudArmor: transition into state 14
[ 3894.761121] CloudArmorLog: /sbin/ip 1392842926
[ 3894.761865] CloudArmor: Event 0: /sbin/ip
[ 3894.762548] CloudArmor: transition into state 14
[ 3895.137161] CloudArmorLog: /sbin/iptables-save 1392842926
[ 3895.151790] CloudArmor: Event 0: /sbin/iptables-save
[ 3895.152594] CloudArmor: transition into state 16
[ 3895.159313] CloudArmor: Event 1: # Generated by iptables-save v1.4.12 on Wed Feb 19 15:48:51 2014|*nat|:PREROUTING ACCEPT [414:48564]|:INPUT ACCEPT [19:11640]|:OUTPUT ACCEPT [249:18922]|:POSTROUTING ACCEPT [644:55846]|:nova-compute-OUTPUT - [0:0]|:nova-compute-POSTROUTING - [0:0]|:nova-compute-PREROUTING - [0:0]|:nova-compute-float-snat - [0:0]|:nova-compute-snat - [0:0]|:nova-postrouting-bottom - [0:0]|[1:335] -A PREROUTING -j nova-compute-PREROUTING|[13:1068] -A OUTPUT -j nova-compute-OUTPUT|[13:1068] -A POSTROUTING -j nova-compute-POSTROUTING|[614:53690] -A POSTROUTING -j nova-postrouting-bottom|[0:0] -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535|[0:0] -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p udp -j MASQUERADE --to-ports 1024-65535|[0:0] -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE|[13:1068] -A nova-compute-snat -j nova-compute-float-snat|[13:1068] -A nova-postrouting-bottom -j nova-compute-snat|COMMIT|# Completed on
[ 3895.167346] CloudArmor: transition into state 25
[ 3895.210038] CloudArmorLog: /sbin/iptables-restore 1392842926
[ 3895.210880] CloudArmor: Event 0: /sbin/iptables-restore
[ 3895.211616] CloudArmor: transition into state 15
[ 3895.217106] CloudArmor: Event 1: # Generated by iptables-save v1.4.12 on Wed Feb 19 15:48:51 2014|*nat|:PREROUTING ACCEPT [414:48564]|:INPUT ACCEPT [19:11640]|:OUTPUT ACCEPT [249:18922]|:POSTROUTING ACCEPT [644:55846]|:nova-compute-OUTPUT - [0:0]|:nova-compute-snat - [0:0]|:nova-compute-PREROUTING - [0:0]|:nova-compute-float-snat - [0:0]|:nova-compute-POSTROUTING - [0:0]|:nova-postrouting-bottom - [0:0]|[0:0] -A PREROUTING -j nova-compute-PREROUTING|[0:0] -A OUTPUT -j nova-compute-OUTPUT|[0:0] -A POSTROUTING -j nova-compute-POSTROUTING|[0:0] -A nova-postrouting-bottom -j nova-compute-snat|[0:0] -A nova-compute-snat -j nova-compute-float-snat|[614:53690] -A POSTROUTING -j nova-postrouting-bottom|[0:0] -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535|[0:0] -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -p udp -j MASQUERADE --to-ports 1024-65535|[0:0] -A POSTROUTING -s 192.168.122.0/24 ! -d 192.168.122.0/24 -j MASQUERADE|COMMIT|# Completed on Wed Feb 19 15:48:
[ 3895.224962] CloudArmor: transition into state 24
[ 3895.380159] device vnet0 entered promiscuous mode
[ 3895.442121] br100: port 2(vnet0) entering forwarding state
[ 3895.444197] br100: port 2(vnet0) entering forwarding state
[ 3896.890819] CloudArmorLog: /usr/bin/tee 1392842926
[ 3896.891253] CloudArmor: Event 0: /usr/bin/tee
[ 3896.891991] CloudArmor: transition into state 22
[ 3896.898507] CloudArmor: Event 1: 1
[ 3896.899288] CloudArmor: transition into state 27
[ 3896.900013] CloudArmor: FINISH STATE
[ 3897.382304] CloudArmorLog: --------------------------------END-----------------------------------------

