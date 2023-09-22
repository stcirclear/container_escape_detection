# Source code

目前移植的有exec监控、open监控、syscall监控三个功能。(后面根据功能再进行补充)

**TASK**
* [x] process，添加可选的权限比较机制：capabilities √；namespaces TODO；
* [x] open，1.read bug解决；2.添加可选的黑名单机制
* [ ] syscall，利用sysdig模块收集容器启动时的系统调用，与监控到的运行时系统调用结合，生成seccomp文件
* [ ] syscall有bug？输入echo命令检测不到发生了什么系统调用？；sysrecord检测到的和strace检测到的不一样？正常吗
* [x] pre-check模块：提取用户输入命令中的镜像名称，用trivy进行扫描
* [ ] 信息聚合与展示：各模块输出到文件，main.py读取并展示？
* [x] main.py：增加 告警or拦截 选项

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
sudo python3 main.py -a alert run -c "sudo docker run -itd --rm --name=test alpine /bin/sh" -s alpine
```
或者
```shell
sudo python3 main.py -a alert monitor -p 1234
```

## 说明
### 1. 
由于seccomp文件只能在容器启动时（？是否有别的方案）进行设置，暂时考虑容器的两种情况：1，容器已经启动 2，容器使用main.py启动

- 对于1，执行syscall调用监控、file操作监控、process操作监控，可以生成seccomp文件但不能应用

- 对于2，需要预启动容器，模拟容器正常任务流，执行syscall调用监控（这个监控应该是整个容器生命周期的，包括启动、执行、停止，可以使用其它工具，比如sysdig），利用收集的syscall生成seccomp文件，然后启动容器，并添加参数“--security-opt seccomp=seccomp.json”。随后，执行file操作监控、process操作监控（syscall调用监控可以不做？）

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

开启一个终端，运行一个特权容器，并将vuls/privileged_container文件夹中的poc.sh脚本拷贝进容器中。

```shell
sudo python3 main.py -a alert run -c "sudo docker run -itd --rm --name privileged_container --privileged ubuntu /bin/bash " -s ubuntu

cd vuls/privileged_container
sudo docker run -itd --rm --name privileged_container --privileged ubuntu /bin/bash   #运行一个特权容器
sudo docker cp poc.sh privileged_container  #拷贝漏洞利用文件进容器
sudo docker top privileged_container  #查看容器进程号，需要的是如下所示的PPID，此处为8105
UID                 PID                 PPID                C                   STIME               TTY                 TIME                CMD
root                8138                8105                0                   00:56               pts/0               00:00:00            /bin/bash
root                15644               8105                0                   01:23               pts/1               00:00:00            /bin/bash

```

开启一个终端，在该终端中启动ebpf漏洞检测程序。

```shell
cd src
sudo ./procrecord -p {容器进程号8105}
```

监控程序启动后，运行容器的交互界面，并利用poc.sh实现特权容器逃逸。

```shell
sudo docker exec -it privileged_container /bin/bash

# 容器内
mkdir host
mount /dev/sda1 /host   #/dev/sda1根据本机实际情况修改
chroot /host
```

与此同时，监控程序可以检测到容器进程根目录发生改变。
### 2. CVE-2022-0492

### 3. CVE-2019-5736
