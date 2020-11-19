---
layout: default
title: 手动搭建Kubernetes
---

## 1、组件版本说明（参考）

| **序号** | **组件**               | **版本**   | **备注** |
| -------- | ---------------------- | ---------- | -------- |
| 1        | kubernetes             | v1.16.8    |          |
| 2        | etcd                   | v3.3.20    |          |
| 3        | docker                 | v18.09.6   |          |
| 4        | flannel                | v0.11.0    |          |
| 5        | coredns                | v1.6.7     |          |
| 6        | dashboard              | v2.0.0-rc4 |          |
| 7        | k8s-prometheus-adapter | v0.5.0     |          |
| 8        | prometheus-operator    | v0.38.0    |          |
| 9        | prometheus             | v2.15.2    |          |
| 10       | elasticsearch、kibana  | v7.2.0     |          |
| 11       | cni-plugins            | v0.8.5     |          |
| 12       | metrics-server         | v0.3.6     |          |
| 13       | weave                  | v1.13.0    |          |
| 14       | kubeapps               | v1.8.2     |          |
| 15       | helm                   | v3.1.0     |          |
| 16       | grafana                | v1.13.0    |          |
| 17       | traefik                | v2.1       |          |

 

**主要配置策略**

kube-apiserver：

- 使用节点本地 nginx 4 层透明代理实现高可用；
- 关闭非安全端口 8080 和匿名访问；
- 在安全端口 6443 接收 https 请求；
- 严格的认证和授权策略 (x509、token、RBAC)；
- 开启 bootstrap token 认证，支持 kubelet TLS bootstrapping；
- 使用 https 访问 kubelet、etcd，加密通信；

 

kube-controller-manager：

- 3 节点高可用；
- 关闭非安全端口，在安全端口 10252 接收 https 请求；
- 使用 kubeconfig 访问 apiserver 的安全端口；
- 自动 approve kubelet 证书签名请求 (CSR)，证书过期后自动轮转；
- 各 controller 使用自己的 ServiceAccount 访问 apiserver；

 

kube-scheduler：

- 3 节点高可用；
- 使用 kubeconfig 访问 apiserver 的安全端口；

 

kubelet：

- 使用 kubeadm 动态创建 bootstrap token，而不是在 apiserver 中静态配置；
- 使用 TLS bootstrap 机制自动生成 client 和 server 证书，过期后自动轮转；
- 在 KubeletConfiguration 类型的 JSON 文件配置主要参数；
- 关闭只读端口，在安全端口 10250 接收 https 请求，对请求进行认证和授权，拒绝匿名访问和非授权访问；
- 使用 kubeconfig 访问 apiserver 的安全端口；

 

kube-proxy：

- 使用 kubeconfig 访问 apiserver 的安全端口；
- 在 KubeProxyConfiguration 类型的 JSON 文件配置主要参数；
- 使用 ipvs 代理模式；

 

集群插件：

- DNS：使用功能、性能更好的 coredns；
- Dashboard：支持登录认证；
- Metric：metrics-server，使用 https 访问 kubelet 安全端口；
- Log：Elasticsearch、Fluend、Kibana；
- Registry 镜像库：docker-registry、harbor；

 

## 2、系统初始化

**集群规划**

- NFS Server：   172.16.200.10
- Kubernetes-01：172.16.200.11
- Kubernetes-02：172.16.200.12
- Kubernetes-03：172.16.200.13

这里我们准备4台主机，NFS Server作为NFS后端存储、部署NFS服务提供存储能力。另外三台机器混合部署etcd、master集群和woker集群。

注：如果没有特殊说明，本小节所有操作需要在所有节点上执行本文档的初始化操作。

 

**配置主机名**

```
# 可以将下面的节点名称替换为自己的主机名称
hostnamectl set-hostname NFS Server
hostnamectl set-hostname Kubernetes-01
hostnamectl set-hostname Kubernetes-02
hostnamectl set-hostname Kubernetes-03
```

 

如果 DNS 不支持主机名称解析，还需要在每台机器的 /etc/hosts 文件中添加主机名和 IP 的对应关系：

```
cat >> /etc/hosts <<EOF
172.16.200.10  NFS Server
172.16.200.11  Kubernetes-01
172.16.200.12  Kubernetes-02
172.16.200.13  Kubernetes-03 
EOF
```



**添加节点SSH互信**

本操作只需要在 Kubernetes-01 节点上进行，设置 root 账户可以无密码登录所有节点：

```
ssh-keygen -t rsa 
ssh-copy-id root@Kubernetes-01
ssh-copy-id root@Kubernetes-02
ssh-copy-id root@Kubernetes-03
ssh-copy-id root@NFS Server
```

**更新PATH变量**

```
echo 'PATH=/opt/k8s/bin:$PATH' >>/root/.bashrc
source /root/.bashrc
```

注：/opt/k8s/bin 目录保存本文档下载安装的程序。

**安装依赖包**

```shell
yum install -y epel-release
yum install -y chrony conntrack ipvsadm ipset jq iptables curl sysstat libseccomp wget socat git

#conntrack:操作netfilter连接跟踪表并保持高可用
#ipvsadm：管理Linux Virtual Server 的工具
#ipset：Manage Linux IP sets
#jq：Command-line JSON processor
#sysstat：Linux性能监视工具的集合
#libseccomp：增强的 seccomp 库,而Secure Computing Mode (seccomp) 是一种内核特性，它允许您从容器中过滤对内核的系统调用
#socat：Socat 是 Linux 下的一个多功能的网络工具,可以看做是 Netcat 的加强版。
```

[LINUX CAPABILITIES AND SECCOMP](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/container_security_guide/linux_capabilities_and_seccomp)

[Socat 入门教程](https://www.hi-linux.com/posts/61543.html)

注：本文档的 kube-proxy 使用 ipvs 模式，ipvsadm 为 ipvs 的管理工具； etcd 集群各机器需要时间同步，chrony 用于系统时间同步。

**关闭防火墙**

```shell
systemctl stop firewalld
systemctl disable firewalld
iptables -F && iptables -X && iptables -F -t nat && iptables -X -t nat
iptables -P FORWARD ACCEPT

#-F:刷新选中的链(如果没有给定链，则刷新表中的所有链)。这相当于逐一删除所有规则
#-X:删除指定的可选用户定义链。必须没有对链的引用。如果存在引用规则，则必须在删除链之前删除或替换引用规则。链必须是空的，即不包含任何规则。如果没有给出参数，它将尝试删除表中的所有非内建链
#-t:此选项指定命令应该操作的数据包匹配表
#-P:将链的策略设置为给定的规则。只有内置(非用户定义)链可以拥有策略，而且内置链和用户定义链都不能是策略目标
```

注：关闭防火墙，清理防火墙规则，设置默认转发策略。

 **关闭swap分区**

```
swapoff -a
sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
```

注：关闭 swap 分区，否则kubelet 会启动失败(可以设置 kubelet 启动参数 --fail-swap-on 为 false 关闭 swap 检查)。

**关闭SELinux**

```
setenforce 0
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
```

注：关闭 SELinux，否则 kubelet 挂载目录时可能报错 Permission denied。

**优化内核参数**

```shell
cat > kubernetes.conf <<EOF
# 1 表示 二层的网桥在转发包时也会被iptables的FORWARD规则所过滤
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
# 1 表示 开启Linux系统的路由转发功能
net.ipv4.ip_forward=1

# 表示开启TCP连接中TIME-WAIT sockets的快速回收，默认为0，表示关闭
net.ipv4.tcp_tw_recycle=0

# 增加内核内部的ARP缓存大小
net.ipv4.neigh.default.gc_thresh1=1024
net.ipv4.neigh.default.gc_thresh2=2048
net.ipv4.neigh.default.gc_thresh3=4096

# 不使用SWAP分区
vm.swappiness=0

# 1 表示 内核允许分配所有的物理内存，而不管当前的内存状态如何
vm.overcommit_memory=1

# 0：内存不足时，启动 OOM killer
vm.panic_on_oom=0

# 表示每一个real user ID可创建的inotify instatnces的数量上限，默认128
fs.inotify.max_user_instances=8192
# 表示同一用户同时可以添加的watch数目（watch一般是针对目录，决定了同时同一用户可以监控的目录数量）
fs.inotify.max_user_watches=1048576
# 设置Linux内核将分配的最大文件句柄数量。通常可设置为 total_Mem(M)/4 * 256
fs.file-max=52706963
# nr_open是单个进程可分配的最大文件数
fs.nr_open=52706963

# 禁用ipv6
net.ipv6.conf.all.disable_ipv6=1

# 最大跟踪连接数
net.netfilter.nf_conntrack_max=2310720
EOF
cp kubernetes.conf  /etc/sysctl.d/kubernetes.conf
sysctl -p /etc/sysctl.d/kubernetes.conf
```

[关于gc_thresh可能出现的问题](https://zhuanlan.zhihu.com/p/94413312)

inotify API提供了一种监视文件系统事件的机制。Inotify可以用于监视单个文件，也可以用于监视目录。当一个目录被监视时，inotify将返回目录本身和目录内文件的事件。`yum install inotify-tools` ，安装inotify的工具。



注：关闭 tcp_tw_recycle，否则与 NAT 冲突，可能导致服务不通。

 

**配置系统时区**

```
timedatectl set-timezone Asia/Shanghai
```

 

**配置时钟同步**

查看同步状态：

```
timedatectl status
```

如果正确、输出信息如下（这里配的时候忘记截图了、后面补的截图）：

注：System clock synchronized: yes，表示时钟已同步； NTP service: active，表示开启了时钟同步服务。

 

**写入硬件时钟**

```shell
# 将当前的 UTC 时间写入硬件时钟
timedatectl set-local-rtc 0

# 重启依赖于系统时间的服务
systemctl restart rsyslog 
systemctl restart crond

#rsyslog：centos7的默认日志系统，用于在ip网络中转发日志信息
#crond：定时任务的守护进程
```

 

**关闭无关服务**

```
systemctl stop postfix && systemctl disable postfix
```

 

**创建配置目录**

创建接下来要使用的相关安装目录：

```
mkdir -p /opt/k8s/{bin,work} /etc/{kubernetes,etcd}/cert
```

 

**分发集群配置参数**

后续使用的环境变量都定义在文件 environment.sh 中，请根据自己的机器、网络情况修改：

```shell
#!/usr/bin/bash

# 生成 EncryptionConfig 所需的加密 key
export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

# 集群各机器 IP 数组
export NODE_IPS=(172.16.200.11 172.16.200.12 172.16.200.13)

# 集群各 IP 对应的主机名数组
export NODE_NAMES=(Kubernetes-01 Kubernetes-02 Kubernetes-03)

# etcd 集群服务地址列表
export ETCD_ENDPOINTS="https://172.16.200.11:2379,https://172.16.200.12:2379,https://172.16.200.13:2379"

# etcd 集群间通信的 IP 和端口
export ETCD_NODES="Kubernetes-01=https://172.16.200.11:2380,Kubernetes-02=https://172.16.200.12:2380,Kubernetes-03=https://172.16.200.13:2380"

# kube-apiserver 的反向代理(kube-nginx)地址端口
export KUBE_APISERVER="https://127.0.0.1:8443"

# 节点间互联网络接口名称
export IFACE="ens160"

# etcd 数据目录
export ETCD_DATA_DIR="/data/k8s/etcd/data"

# etcd WAL 目录，建议是 SSD 磁盘分区，或者和 ETCD_DATA_DIR 不同的磁盘分区
export ETCD_WAL_DIR="/data/k8s/etcd/wal"

# k8s 各组件数据目录
export K8S_DIR="/data/k8s/k8s"

## DOCKER_DIR 和 CONTAINERD_DIR 二选一
# docker 数据目录
export DOCKER_DIR="/data/k8s/docker"

# containerd 数据目录
# export CONTAINERD_DIR="/data/k8s/containerd"

## 以下参数一般不需要修改
# TLS Bootstrapping 使用的 Token，可以使用命令 
# head -c 16 /dev/urandom | od -An -t x | tr -d ' ' 生成
# od：以八进制和其他格式转储文件，-A:输出格式偏移，n表示None，-t：输出格式，x表示16进制

BOOTSTRAP_TOKEN="41f7e4ba8b7be874fcff18bf5cf41a7c"

# 最好使用 当前未用的网段 来定义服务网段和 Pod 网段
# 服务网段，部署前路由不可达，部署后集群内路由可达(kube-proxy 保证)
SERVICE_CIDR="10.254.0.0/16"

# Pod 网段，建议 /16 段地址，部署前路由不可达，部署后集群内路由可达(flanneld 保证)
CLUSTER_CIDR="172.30.0.0/16"

# 配置flanneld的FLANNEL_ETCD_PREFIX文件目录
export FLANNEL_ETCD_PREFIX="/kubernetes/network"
# 服务端口范围 (NodePort Range)
export NODE_PORT_RANGE="30000-32767"

# kubernetes 服务 IP (一般是 SERVICE_CIDR 中第一个IP)
export CLUSTER_KUBERNETES_SVC_IP="10.254.0.1"

# 集群 DNS 服务 IP (从 SERVICE_CIDR 中预分配)
export CLUSTER_DNS_SVC_IP="10.254.0.2"

# 集群 DNS 域名（末尾不带点号）
export CLUSTER_DNS_DOMAIN="cluster.local"

# 将二进制目录 /opt/k8s/bin 加到 PATH 中
export PATH=/opt/k8s/bin:$PATH
```

注：因为我采用了flannel网络、所以这里我在原文的基础之上添加了export FLANNEL_ETCD_PREFIX="/kubernetes/network"变量、禁止了containerd 数据目录。

 

把上面的 environment.sh 文件修改完成之后保存到 /opt/k8s/bin/ 目录下面，然后拷贝到所有节点（修改完上面的文件之后再执行下面的操作）：

```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp environment.sh root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/361872012283102108.png)

 

**内核升级**

CentOS 7.x 系统自带的 3.10.x 内核存在一些 Bugs，导致运行的 Docker、Kubernetes 不稳定，例如：

- 高版本的 docker(1.13 以后) 启用了 3.10 kernel 实验支持的 kernel memory account 功能(无法关闭)，当节点压力大如频繁启动和停止容器时会导致 cgroup memory leak；
- 网络设备引用计数泄漏，会导致类似于报错："kernel:unregister_netdevice: waiting for eth0 to become free. Usage count = 1";

解决方案如下：

- 升级内核到 4.4.X 以上；
- 或者，手动编译内核，disable CONFIG_MEMCG_KMEM 特性；
- 或者，安装修复了该问题的 Docker 18.09.1 及以上的版本。但由于 kubelet 也会设置 kmem（它 vendor 了 runc），所以需要重新编译 kubelet 并指定 GOFLAGS="-tags=nokmem"；

```shell
git clone --branch v1.14.1 --single-branch --depth 1 https://github.com/kubernetes/kubernetes
cd kubernetes
KUBE_GIT_VERSION=v1.14.1 ./build/run.sh make kubelet GOFLAGS="-tags=nokmem"
```

 

这里采用升级内核的解决办法：

```shell
rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
# 安装完成后检查 /boot/grub2/grub.cfg 中对应内核 menuentry 中是否包含 initrd16 配置，如果没有，再安装一次！
yum --enablerepo=elrepo-kernel install -y kernel-lt
# 设置开机从新内核启动
grub2-set-default 0
```

 

执行完上面所有的操作之后我们就可以重启所有主机了：

```
sync
reboot
```

 

本小节参考文档：

- 系统内核相关参数参考：[https://docs.openshift.com/enterprise/3.2/admin_guide/overcommit.html](https://blog.z0ukun.com/wp-content/themes/begin4.6/inc/go.php?url=https://docs.openshift.com/enterprise/3.2/admin_guide/overcommit.html)
- 3.10.x 内核 kmem bugs 相关的讨论和解决办法：
  - [https://github.com/kubernetes/kubernetes/issues/61937](https://blog.z0ukun.com/wp-content/themes/begin4.6/inc/go.php?url=https://github.com/kubernetes/kubernetes/issues/61937)
  - [https://support.mesosphere.com/s/article/Critical-Issue-KMEM-MSPH-2018-0006](https://blog.z0ukun.com/wp-content/themes/begin4.6/inc/go.php?url=https://support.mesosphere.com/s/article/Critical-Issue-KMEM-MSPH-2018-0006)
  - [https://pingcap.com/blog/try-to-fix-two-linux-kernel-bugs-while-testing-tidb-operator-in-k8s/](https://blog.z0ukun.com/wp-content/themes/begin4.6/inc/go.php?url=https://pingcap.com/blog/try-to-fix-two-linux-kernel-bugs-while-testing-tidb-operator-in-k8s/)

## 3、创建CA证书和秘钥

为确保安全，kubernetes 系统各组件需要使用 x509 证书对通信进行加密和认证。 CA (Certificate Authority) 是自签名的根证书，用来签名后续创建的其它证书。 CA 证书是集群所有节点共享的，只需要创建一次，后续用它签名其它所有证书。 本小节使用 CloudFlare 的 PKI 工具集 cfssl 创建所有证书。

注：如果没有特殊指明，本小节所有操作均在 **Kubernetes-01** 节点上执行。

**安装 cfssl 工具集**

cfssl github项目地址：[https://github.com/cloudflare/cfssl](https://blog.z0ukun.com/wp-content/themes/begin4.6/inc/go.php?url=https://github.com/cloudflare/cfssl)

```shell
sudo mkdir -p /opt/k8s/cert && cd /opt/k8s/work

wget https://github.com/cloudflare/cfssl/releases/download/v1.4.1/cfssl_1.4.1_linux_amd64
mv cfssl_1.4.1_linux_amd64 /opt/k8s/bin/cfssl

wget https://github.com/cloudflare/cfssl/releases/download/v1.4.1/cfssljson_1.4.1_linux_amd64
mv cfssljson_1.4.1_linux_amd64 /opt/k8s/bin/cfssljson

wget https://github.com/cloudflare/cfssl/releases/download/v1.4.1/cfssl-certinfo_1.4.1_linux_amd64
mv cfssl-certinfo_1.4.1_linux_amd64 /opt/k8s/bin/cfssl-certinfo

chmod +x /opt/k8s/bin/*
export PATH=/opt/k8s/bin:$PAT
echo "alias cfssl='cfssl_linux-amd64'" >> ~/.bashrc
echo "alias cfssljson='cfssljson_linux-amd64'" >> ~/.bashrc

```

 

**创建配置文件**

CA 配置文件用于配置根证书的使用场景 (profile) 和具体参数 (usage，过期时间、服务端认证、客户端认证、加密等)：

```
cd /opt/k8s/work

cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "876000h"
      }
    }
  }
}
EOF
```

- signing：表示该证书可用于签名其它证书（生成的 ca.pem 证书中 CA=TRUE）；
- server auth：表示 client 可以用该该证书对 server 提供的证书进行验证；
- client auth：表示 server 可以用该该证书对 client 提供的证书进行验证；
- "expiry": "876000h"：证书有效期设置为 100 年；

 

**创建证书签名请求文件**

```
cd /opt/k8s/work
cat > ca-csr.json <<EOF
{
  "CN": "kubernetes-ca",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "z0ukun"
    }
  ],
  "ca": {
    "expiry": "876000h"
 }
}
EOF
```

- CN：Common Name：kube-apiserver 从证书中提取该字段作为请求的用户名 (User Name)，浏览器使用该字段验证网站是否合法；

- O：Organization：kube-apiserver 从证书中提取该字段作为请求用户所属的组 (Group)；

- kube-apiserver 将提取的 User、Group 作为 RBAC 授权的用户标识；

- ```
      "C": "<country>",
      "ST": "<state>",
      "L": "<city>",
      "O": "<organization>",
      "OU": "<organization unit>"
  ```

注：不同证书 csr 文件的 CN、C、ST、L、O、OU 组合必须不同，否则可能出现 PEER'S CERTIFICATE HAS AN INVALID SIGNATURE 错误；后续创建证书的 csr 文件时，CN 都不相同（C、ST、L、O、OU 相同），以达到区分的目的。



**生成 CA 密钥（`ca-key.pem`）和证书（`ca.pem`）**

```shell
cd /opt/k8s/work
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
ls ca*

# 查看证书
openssl x509 -noout -text -in ca.pem
# 查看私钥
openssl rsa -noout -text -in ca-key.pem
```

 

**分发证书文件**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/kubernetes/cert"
    scp ca*.pem ca-config.json root@${node_ip}:/etc/kubernetes/cert
  done
```



## 4、部署Kubectl工具

注：本小节介绍安装和配置 kubernetes 命令行管理工具 kubectl 的步骤。本小节只需要部署一次，生成的 kubeconfig 文件是通用的，可以拷贝到需要执行 kubectl 命令的机器的 ~/.kube/config 位置。

注：如果没有特殊指明，本小节所有操作均在 **Kubernetes-01** 节点上执行。

 

**下载Kubectl二进制文件**

```
cd /opt/k8s/work

# 自行解决翻墙下载问题
wget https://dl.k8s.io/v1.16.8/kubernetes-client-linux-amd64.tar.gz 
tar -xzvf kubernetes-client-linux-amd64.tar.gz
```

 

分发到所有使用 kubectl 工具的节点：

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp kubernetes/client/bin/kubectl root@${node_ip}:/opt/k8s/bin/
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```

 

**创建admin证书和私钥**

kubectl 使用 https 协议与 kube-apiserver 进行安全通信，kube-apiserver 对 kubectl 请求包含的证书进行认证和授权。kubectl 后续用于集群管理，所以这里创建具有**最高权限**的 admin 证书。

创建证书签名请求：

```
cd /opt/k8s/work
cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "z0ukun"
    }
  ]
}
EOF
```

- O: system:masters：kube-apiserver 收到使用该证书的客户端请求后，为请求添加组（Group）认证标识 system:masters；
- 预定义的 ClusterRoleBinding cluster-admin 将 Group system:masters 与 Role cluster-admin 绑定，该 Role 授予操作集群所需的最高权限；
- 该证书只会被 kubectl 当做 client 证书使用，所以 hosts 字段为空。

 

**生成证书和私钥：**

```
cd /opt/k8s/work
cfssl gencert -ca=/opt/k8s/work/ca.pem \
  -ca-key=/opt/k8s/work/ca-key.pem \
  -config=/opt/k8s/work/ca-config.json \
  -profile=kubernetes admin-csr.json | cfssljson -bare admin
ls admin*
```

注：忽略警告消息： [WARNING] This certificate lacks a "hosts" field。

 

**创建 kubeconfig 文件**

kubectl 使用 kubeconfig 文件访问 apiserver，该文件包含 kube-apiserver 的地址和认证信息（CA 证书和客户端证书）：

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh

# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/work/ca.pem \
  --embed-certs=true \
  --server=https://${NODE_IPS[0]}:6443 \
  --kubeconfig=kubectl.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=/opt/k8s/work/admin.pem \
  --client-key=/opt/k8s/work/admin-key.pem \
  --embed-certs=true \
  --kubeconfig=kubectl.kubeconfig

# 设置上下文参数
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin \
  --kubeconfig=kubectl.kubeconfig

# 设置默认上下文
kubectl config use-context kubernetes --kubeconfig=kubectl.kubeconfig
```

- --certificate-authority：验证 kube-apiserver 证书的根证书；
- --client-certificate、--client-key：刚生成的 admin 证书和私钥，与 kube-apiserver https 通信时使用；
- --embed-certs=true：将 ca.pem 和 admin.pem 证书内容嵌入到生成的 kubectl.kubeconfig 文件中(否则，写入的是证书文件路径，后续拷贝 kubeconfig 到其它机器时，还需要单独拷贝证书文件，不方便。)；
- --server：指定 kube-apiserver 的地址，这里指向第一个节点上的服务。

 

**分发 kubeconfig 文件**

分发到所有使用 kubectl 命令的节点：

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ~/.kube"
    scp kubectl.kubeconfig root@${node_ip}:~/.kube/config
  done
```

## 5、部署Etcd集群

etcd 是基于 Raft 的分布式 KV 存储系统，由 CoreOS 开发，常用于服务发现、共享配置以及并发控制（如 leader 选举、分布式锁等）；kubernetes 使用 etcd 集群持久化存储所有 API 对象、运行数据。

本小节介绍如何部署一个三节点高可用 etcd 集群的步骤：

- 下载和分发 etcd 二进制文件；
- 创建 etcd 集群各节点的 x509 证书，用于加密客户端(如 etcdctl) 与 etcd 集群、etcd 集群之间的通信；
- 创建 etcd 的 systemd unit 文件，配置服务参数；
- 检查集群工作状态；

etcd 集群节点名称和 IP 如下：

- Kubernetes-01：172.16.200.11
- Kubernetes-02：172.16.200.12
- Kubernetes-03：172.16.200.13

注：如果没有特殊指明，本小节所有操作**均在 Kubernetes-01 节点上执行**；需要特别注意 flanneld 与本小节安装的 etcd v3.4.x 不兼容，如果要安装 flanneld（如果网络使用 calio 则不需要修改），则需要将 etcd **降级到 v3.3.x 版本**。

 

**下载etcd二进制文件**

etcd下载地址：[https://github.com/etcd-io/etcd/releases](https://blog.z0ukun.com/wp-content/themes/begin4.6/inc/go.php?url=https://github.com/etcd-io/etcd/releases)

这里我们为了兼容Flannel网络插件、安装etcd v3.3.20版本。

```
cd /opt/k8s/work
wget https://github.com/coreos/etcd/releases/download/v3.3.20/etcd-v3.3.20-linux-amd64.tar.gz
tar -xvf etcd-v3.3.20-linux-amd64.tar.gz
```

 

**分发二进制文件到集群所有节点：**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp /opt/k8s/work/etcd-v3.3.20-linux-amd64/etcd* root@${node_ip}:/opt/k8s/bin
    ssh root@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```

 

**创建etcd证书和私钥**

创建证书签名请求：

```
cd /opt/k8s/work
cat > etcd-csr.json <<EOF
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "172.16.200.11",
    "172.16.200.12",
    "172.16.200.13"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "z0ukun"
    }
  ]
}
EOF
```

- hosts：指定授权使用该证书的 etcd 节点 IP 列表，需要将 etcd 集群所有节点 IP 都列在其中。

 

**生成证书和私钥：**

```
cd /opt/k8s/work
cfssl gencert -ca=/opt/k8s/work/ca.pem \
    -ca-key=/opt/k8s/work/ca-key.pem \
    -config=/opt/k8s/work/ca-config.json \
    -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
ls etcd*pem
```

 

**分发生成的证书和私钥到各 etcd 节点：**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p /etc/etcd/cert"
    scp etcd*.pem root@${node_ip}:/etc/etcd/cert/
  done
```

 

**创建etcd的systemd unit模板文件**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
cat > etcd.service.template <<EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Type=notify
WorkingDirectory=${ETCD_DATA_DIR}
ExecStart=/opt/k8s/bin/etcd \\
  --data-dir=${ETCD_DATA_DIR} \\
  --wal-dir=${ETCD_WAL_DIR} \\
  --name=##NODE_NAME## \\
  --cert-file=/etc/etcd/cert/etcd.pem \\
  --key-file=/etc/etcd/cert/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-cert-file=/etc/etcd/cert/etcd.pem \\
  --peer-key-file=/etc/etcd/cert/etcd-key.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --listen-peer-urls=https://##NODE_IP##:2380 \\
  --initial-advertise-peer-urls=https://##NODE_IP##:2380 \\
  --listen-client-urls=https://##NODE_IP##:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls=https://##NODE_IP##:2379 \\
  --initial-cluster-token=etcd-cluster-0 \\
  --initial-cluster=${ETCD_NODES} \\
  --initial-cluster-state=new \\
  --auto-compaction-mode=periodic \\
  --auto-compaction-retention=1 \\
  --max-request-bytes=33554432 \\
  --quota-backend-bytes=6442450944 \\
  --heartbeat-interval=250 \\
  --election-timeout=2000
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/367571111109125107.png)

- WorkingDirectory、--data-dir：指定工作目录和数据目录为 ${ETCD_DATA_DIR}，需在启动服务前创建这个目录；
- --wal-dir：指定 wal 目录，为了提高性能，一般使用 SSD 或者和 --data-dir 不同的磁盘；
- --name：指定节点名称，当 --initial-cluster-state 值为 new 时，--name 的参数值必须位于 --initial-cluster 列表中；
- --cert-file、--key-file：etcd server 与 client 通信时使用的证书和私钥；
- --trusted-ca-file：签名 client 证书的 CA 证书，用于验证 client 证书；
- --peer-cert-file、--peer-key-file：etcd 与 peer 通信使用的证书和私钥；
- --peer-trusted-ca-file：签名 peer 证书的 CA 证书，用于验证 peer 证书。

 

**为各节点创建和分发 etcd systemd unit 文件**

替换模板文件中的变量，为各节点创建 systemd unit 文件：

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for (( i=0; i < 3; i++ ))
  do
    sed -e "s/##NODE_NAME##/${NODE_NAMES[i]}/" -e "s/##NODE_IP##/${NODE_IPS[i]}/" etcd.service.template > etcd-${NODE_IPS[i]}.service 
  done

ls *.service
```

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/37001015617281.png)

- NODE_NAMES 和 NODE_IPS 为相同长度的 bash 数组，分别为节点名称和对应的 IP。

 

**分发生成的 systemd unit 文件：**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp etcd-${node_ip}.service root@${node_ip}:/etc/systemd/system/etcd.service
  done
```

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/367290428423249.png)

 

**启动etcd服务**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "mkdir -p ${ETCD_DATA_DIR} ${ETCD_WAL_DIR}"
    ssh root@${node_ip} "systemctl daemon-reload && systemctl enable etcd && systemctl restart etcd " &
  done
```

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/3617571116186104.png)

- 切记必须先创建 etcd 数据目录和工作目录;
- etcd 进程首次启动时会等待其它节点的 etcd 加入集群，命令 systemctl start etcd 会卡住一段时间，为正常现象。

 

**检查启动结果**

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    ssh root@${node_ip} "systemctl status etcd|grep Active"
  done
```

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/36814121594135142.png)

注：确保状态为 active (running)，否则可以通过 journalctl -u etcd 查看日志，确认原因。

 

**验证服务状态**

部署完 etcd 集群后，在任一 etcd 节点上执行如下命令：

```
cd /opt/k8s/work
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    /opt/k8s/bin/etcdctl \
    --endpoints=https://${node_ip}:2379 \
    --cacert=/etc/kubernetes/cert/ca.pem \
    --cert=/etc/etcd/cert/etcd.pem \
    --key=/etc/etcd/cert/etcd-key.pem endpoint health
  done
```

- 3.4.X 版本的 etcd/etcdctl 默认启用了 V3 API，所以执行 etcdctl 命令时不需要再指定环境变量 ETCDCTL_API=3；
- 从 K8S 1.13 开始，不再支持 v2 版本的 etcd。

预期输出：

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/3175711176968109.png)

输出均为 healthy 时表示集群服务正常。

 

**查看当前的leader**

```
source /opt/k8s/bin/environment.sh
/opt/k8s/bin/etcdctl \
  -w table --cacert=/etc/kubernetes/cert/ca.pem \
  --cert=/etc/etcd/cert/etcd.pem \
  --key=/etc/etcd/cert/etcd-key.pem \
  --endpoints=${ETCD_ENDPOINTS} endpoint status
```

 

输出信息如下：

![手动搭建Kubernetes-v1.16.8高可用集群（完结）](http://blog.z0ukun.com/wp-content/uploads/2020/04/36018161001445261.png)

可见，当前的 leader 为 172.16.200.13。
