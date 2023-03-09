# container_escape_detection

## 环境配置
1. 系统及内核版本  
Ubuntu 18.04, 5.4.0-109-generic
2. 软件版本及安装方法
```
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```
**Clang版本需要10+**

## 模块介绍

### 数据采集模块

    1. syscall监控

    2. exec监控

    3. fileopen监控

    4. 可选——容器间访问行为监控

### 数据处理模块
&ensp;syscall 统计数据用于seccomp  
&ensp;sys_execve、sys_openat、sock事件等用于日志记录，可以定义过滤策略，对危险行为报警

### 权限控制模块
&ensp;seccomp  
&ensp;capabilities

### 其他
- 静态预检测  
<https://github.com/aquasecurity/trivy>
- 异常事件检测  
<https://ieeexplore.ieee.org/abstract/document/8807263>
- lsm_ksri  
<https://github.com/mrtc0/bouheki>

## 测试步骤
