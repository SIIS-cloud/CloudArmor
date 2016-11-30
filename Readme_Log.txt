Installing Logging infrastructure

1. download kernel patch 

	https://siissvn.cse.psu.edu/svn/src/cloud10/cloudarmor/patch.log.2.8

2. apply kernel patch.
	enter your kernel source directory, in our case linux-3.2.1
	cd linux-3.2.1
	patch -p1 < ../patch.log.2.8

3. compile kernel.
	On VM host & within VM
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
	start nova-compute
		nova-compute

6. testing

	in mega.cse.psu.edu, run nova commands. For example, following command starts a VM. You should change parameters accordingly
		nova boot my_vm --key-name XXX --flavor 6 --image 47ec5f2c-2608-4d4a-af78-f683bd5cfdd5 --availability-zone nova:XXX
	in your nova-compute VM,
		dmesg | grep Cloud

	You shuold be able to see logs in the following fomat. It starts and ends with dashed lines.

[  229.108651] CloudArmor: ------------------------run_instance---------------------------------
[  231.978983] CloudArmor: /usr/bin/qemu-img 1391891241
[  232.103454] CloudArmor: /usr/bin/qemu-nbd 1391891241
[  232.146705] CloudArmor: /sbin/kpartx 1391891241
[  232.185279] CloudArmor: /bin/mount 1391891241
[  232.294987] CloudArmor: /bin/readlink 1391891241
[  232.317170] CloudArmor: /bin/mkdir 1391891241
[  232.347914] CloudArmor: /bin/readlink 1391891241
[  232.365745] CloudArmor: /bin/chown 1391891241
[  232.396151] CloudArmor: /bin/readlink 1391891241
[  232.413944] CloudArmor: /bin/chmod 1391891241
[  232.438037] CloudArmor: /bin/readlink 1391891241
[  232.471429] CloudArmor: /usr/bin/tee 1391891241
[  232.494151] CloudArmor: /bin/readlink 1391891241
[  232.515597] CloudArmor: /bin/chmod 1391891241
[  232.537482] CloudArmor: /bin/readlink 1391891241
[  232.556449] CloudArmor: /bin/readlink 1391891241
[  232.593797] CloudArmor: /bin/umount 1391891241
[  232.800128] CloudArmor: /sbin/kpartx 1391891241
[  232.823968] CloudArmor: /usr/bin/qemu-nbd 1391891241
[  233.743521] CloudArmor: /sbin/ip 1391891241
[  233.791095] CloudArmor: /sbin/brctl 1391891241
[  233.806887] CloudArmor: /sbin/ip 1391891241
[  233.833859] CloudArmor: /sbin/ip 1391891241
[  234.046109] CloudArmor: /sbin/iptables-save 1391891241
[  234.061142] CloudArmor: /sbin/iptables-restore 1391891241
[  234.106492] CloudArmor: /sbin/iptables-save 1391891241
[  234.143146] CloudArmor: /sbin/iptables-restore 1391891241
[  235.902156] CloudArmor: /usr/bin/tee 1391891241
[  236.439393] CloudArmor: --------------------------------END-----------------------------------------

