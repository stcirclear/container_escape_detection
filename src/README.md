# Source code

目前移植的有exec监控、open监控、syscall监控计数三个功能。(后面根据功能再进行补充)

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
sudo python3 main.py
```