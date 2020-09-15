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

### Tool set install
the following tools are required
```
yum update
yum install -y libbpf llvm clang elfutils-libelf-devel \
               libpcap-dev gcc-multilib build-essential \
               perf install kernel-headers bpftool bison flex
```


### IPRoute2 upgraded
The default IP utility in IPRoute2 package doesn't support XDP loading.
Upgraded IPRoute2 to latest
```
yum install bison flex
cd /temp
git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
cd iproute2
./configure --prefix=/usr
make && make install
ip -V
```

### Upgrade llvm-toolset-7
The default llvm clang toolset doesn't support XDP, so upgraded it
```
yum install centos-release-scl
yum install llvm-toolset-7
scl enable llvm-toolset-7 bash
```

### Upgrade gcc
```
yum install centos-release-scl
yum install devtoolset-7-gcc*
scl enable devtoolset-7 bash
```
