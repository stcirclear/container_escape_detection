# Source code

目前移植的有exec监控、open监控、syscall监控三个功能。(后面根据功能再进行补充)
* [x] process
* [ ] open
* [x] syscall

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

