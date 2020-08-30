# Setup development and testing environment for XDP-tutorial from Centos 7

## Upgrade OS and toolset
### OS kernel upgrade
The default kernel version of my Centos 7 is 3.5.x.
XDP is shipped to kernel 4.8 perf [wikipedia](https://en.wikipedia.org/wiki/Express_Data_Path).
So, the kernel has to been upgraded to a 4.8 or later.
As Aug 2020, the latest kernel stable version is 5.x. The following steps I used to upgrade kernel.
```
yum --enablerepo=elrepo-kernel install kernel-ml${KERNEL_VERSION} kernel-ml-devel${KERNEL_VERSION} kernel-ml-tools${KERNEL_VERSION} kernel-ml-tools-libs${KERNEL_VERSION} -y   
update GRUB_DEFAULT=0 in /etc/default/grub
reboot
```
