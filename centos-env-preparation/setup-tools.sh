
function package_setup {
  GITROOT="$(dirname $0)"
  pushd .
  cd $PWD/$GITROOT/..
  git submodule update --init

  yum update && \
  yum install -y libbpf llvm clang elfutils-libelf-devel \
                 libpcap-dev gcc-multilib build-essential \
                 perf install kernel-headers bpftool

  popd
}

# make sure iproute2 is the version support XDP
function compile_iproute2 {
  pushd .
  yum install bison flex
  cd /temp
  git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
  cd iproute2
  ./configure --prefix=/usr
  make && make install
  ip -V
  # in my case the ip -V from iproute2-ss170501 to iproute2-5.8.0, and iproute2-5.8.0 loads the xpd successively
  popd
}


function upgrade_clang5 {
  yum install centos-release-scl
  yum install llvm-toolset-7
  scl enable llvm-toolset-7 bash
}
