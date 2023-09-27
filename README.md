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

## 说明
### 1. 
由于seccomp文件只能在容器启动时（？是否有别的方案）进行设置，暂时考虑容器的两种情况：

（1）容器已经启动 （2）容器使用main.py启动

- 对于（1），执行syscall调用监控、file操作监控、process操作监控，可以生成seccomp文件但不能应用

- 对于（2），需要预启动容器，模拟容器正常任务流，执行syscall调用监控（这个监控应该是整个容器生命周期的，包括启动、执行、停止，可以使用其它工具，比如sysdig），利用收集的syscall生成seccomp文件，然后启动容器，并添加参数“--security-opt seccomp=seccomp.json”。随后，执行file操作监控、process操作监控、syscall调用监控

**注意**：使用seccomp要安装一下包

```shell
sudo apt install libseccomp-dev libseccomp2 seccomp
```

### 2.
只做监控或许不够，也要有“响应”？方便展示如何对逃逸进行了防御

参考[bouheki](https://github.com/mrtc0/bouheki/tree/master/pkg/bpf/c)这个，可以对file、mount设置黑名单，但是这个功能需要高版本内核（Linux Kernel >= 5.8.0），可以用ubuntu20.10测试


## 检测漏洞
### 1. 特权容器
> 该逃逸不限docker和Linux内核版本

```shell
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --rm --name privileged_container --privileged ubuntu /bin/bash"
```

监控程序启动后，运行容器的交互界面，并利用poc.sh实现特权容器逃逸。

```shell
sudo docker exec -it privileged_container /bin/bash

# 容器内
mkdir host
mount /dev/sda1 /host   #/dev/sda1根据本机实际情况修改
chroot /host
```

### 2. CVE-2022-0492
```shell
# 只输出到日志，不中断
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --security-opt apparmor=unconfined --security-opt seccomp=unconfined --name=cve0492 --rm ubuntu /bin/bash"

```

### 3. CVE-2019-5736
```shell
sudo python3 main.py -a alert/intercept run -c "sudo docker run -itd --name=cve5736 --rm ubuntu bash"
```
