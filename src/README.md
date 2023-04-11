# Source code

目前移植的有exec监控、open监控、syscall监控三个功能。(后面根据功能再进行补充)

**TASK**
* [x] process，添加可选的权限比较机制：capabilities √；namespaces TODO；
* [ ] open，1.read bug解决；2.添加可选的黑名单机制
* [ ] syscall，利用sysdig模块收集容器启动时的系统调用，与监控到的运行时系统调用结合，生成seccomp文件
* [ ] syscall有bug？输入echo命令检测不到发生了什么系统调用？；sysrecord检测到的和strace检测到的不一样？正常吗
* [ ] pre-check模块：提取用户输入命令中的镜像名称，用trivy进行扫描
* [ ] 信息聚合与展示：各模块输出到文件，main.py读取并展示？
* [x] main.py：增加 告警or拦截 选项

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
sudo python3 ../main.py run -c "sudo docker run -d --name=alpine2 alpine /bin/sh"
```
或者
```shell
sudo python3 ../main.py monitor -p 1234
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

