#!/bin/python
# coding=utf-8

### Container Escape Monitor

import os
import time
import json
import argparse
import subprocess
from multiprocessing import Process
from platform import platform
# from terminal_layout.extensions.choice import *
# from terminal_layout import *

TMP_OUTPUT = "output.txt"
JSON_OUTPUT = "dockerinfo.json"
CONFIG_FILE = "dockerinfo_config.json"
FILE_RECORD = "filerecord.txt"
PROC_RECORD = "procrecord.txt"
SYS_RECORD = "sysrecord.txt"


# 执行命令行命令
def exec_command(cmd, cwd=os.getcwd()):
	# print(f"Run cmd '{cmd}' in '{cwd}'")
	container_id = ""
	try:
		result = subprocess.run(
			cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE)
		if result.returncode != 0:
			msg = f"returncode: {result.returncode} cmd: '{result.args}' err:{result.stderr}"
			print("\033[1;31mERROR:\033[0m \033[0;31m%s\033[0m" % msg)
			return ""
		# 过滤出启动容器的命令
		if "docker run" in cmd:
			container_id = str(result.stdout, encoding='utf-8')
	except Exception as ex:
		import traceback
		traceback.print_exc()
		return ""
	return container_id


# 使用脚本dockerpsns.sh获取docker信息
def get_dockerinfo():
	print("\033[0;32m***** DOCKER INFO GENERATING *****\033[0m")
	cmd = f"sudo bash dockerpsns.sh > {TMP_OUTPUT}"
	exec_command(cmd, os.getcwd())

	json_data = {"Containers": []}
	with open(TMP_OUTPUT, "r") as f:
		data = f.readlines()
		for item in data[1:]:
			# json
			dict_data = {}
			dict_data['CONTAINER-ID'] = item.split()[0]
			dict_data['NAME'] = item.split()[1]
			dict_data['PID'] = int(item.split()[2])
			dict_data['PPID'] = int(item.split()[3])
			dict_data['PATH'] = item.split()[4]
			dict_data['CGROUP'] = item.split()[5]
			dict_data['IPC'] = item.split()[6]
			dict_data['NET'] = item.split()[7]
			dict_data['USER'] = item.split()[8]
			dict_data['UTS'] = item.split()[9]
			json_data['Containers'].append(dict_data)

	with open(CONFIG_FILE) as f:
		config = json.load(f)
		config.update(json_data)

	with open(JSON_OUTPUT, "w") as f:
		f.write(json.dumps(config, indent=4, separators=(',', ': ')))
	print("\033[0;32m***** DOCKER INFO GENERATED ******\033[0m")

	os.remove(TMP_OUTPUT)


# 将container id转换成container的pid
def containerid_to_pid(container_id):
	cmd = f"sudo bash dockerpsns.sh > {TMP_OUTPUT}"
	exec_command(cmd, os.getcwd())

	pid = 0
	with open(TMP_OUTPUT, "r") as f:
		data = f.readlines()
		for item in data[1:]:
			if item.split()[0] == container_id[:12]:
				pid = int(item.split()[2])
				break
			else:
				continue
	os.remove(TMP_OUTPUT)
	return pid


# 将container id转换成container的ppid
def containerid_to_ppid(container_id):
	cmd = f"sudo bash dockerpsns.sh > {TMP_OUTPUT}"
	exec_command(cmd, os.getcwd())

	ppid = 0
	with open(TMP_OUTPUT, "r") as f:
		data = f.readlines()
		for item in data[1:]:
			if item.split()[0] == container_id[:12]:
				ppid = int(item.split()[3])
				break
			else:
				continue
	os.remove(TMP_OUTPUT)
	return ppid


# 新建容器
def start_container(cmd):
	print("\033[0;32m***** STARTING THE CONTAINER *****\033[0m")
	container_id = exec_command(cmd, os.getcwd())
	print("\033[0;32m******* CONTAINER STARTED ********\033[0m")
	return container_id

# 获取当前内核版本号，并转化为十进制数字，如5.8.0 -> 580
def get_kernel_version():
	platform_str = platform()
	version = platform_str.split('-')[1]
	# print(version_num)
	return version
		

# 启动监视器
def start_monitor(pid, action):
	print("\033[0;32m****** STARTING THE MONITOR ******\033[0m")
	# sysrecord
	# cmd = f"sudo ./sysrecord -p {pid}"
	# p1 = Process(target=exec_command, args=(cmd, ))
	# p1.start()

	version = get_kernel_version()
	version_num = 0
	for item in version.split('.'):
		version_num =+ version_num * 10 + int(item)
	need_version = 590
	print("\033[0;32m Current Kernel Version is %s\033[0m" % version)
	# fileopen
	if(version_num >= need_version):
		cmd = f"sudo ./opensnoop -a {action} -p {pid}"
		print("\033[1;32m Execute:\033[0m \033[0;32m%s\033[0m" % cmd)
		p2 = Process(target=exec_command, args=(cmd, ))
		p2.start()
	else:
		print("\033[1;33m Warning:\033[0m \033[0;33mCurrent kernel version is too low to excute opensnoop\033[0m")
	

	# procrecord
	cmd = f"sudo ./procrecord -a {action} -p {pid}"
	print("\033[1;32m Execute:\033[0m \033[0;32m%s\033[0m" % cmd)
	p3 = Process(target=exec_command, args=(cmd, ))
	p3.start()
	print("\033[0;32m******** MONITOR STARTED *********\033[0m")


def display(file):
	while(True):
		with open(file) as f:
			lines = f.readlines()
			for line in lines:
				print(line.strip())
		time.sleep(2)
		os.system("clear")


def parse_args():
	parser = argparse.ArgumentParser(description='Container Escape Monitor.')

	# action参数是否取消，阻断的话需要用到bpf_send_signal(KILL)
	parser.add_argument('-a', '--action', action='store', help='monitor action', choices=['alert', 'intercept'], required=True)
	# 添加参数
	subparsers = parser.add_subparsers(help='sub-command help')
	parser_a = subparsers.add_parser('monitor', help='monitor mode')
	parser_a.add_argument('-p', '--pid',  action='store',
						  help='process id', required=True)
	parser_b = subparsers.add_parser('run', help='run mode')
	parser_b.add_argument('-c', '--command', action='store',
						  help='container run command', required=True)
	parser_b.add_argument('-s', '--scan', action='store',
						  help='scan the image or not')

	# 解析参数
	args = parser.parse_args()
	return args


def main():
	# parse args
	args = parse_args()
	if hasattr(args, 'pid') and hasattr(args, 'action'):
		pid = int(args.pid)
		action = args.action
		# print(pid)
		# 启动monitor
		get_dockerinfo()
		start_monitor(pid, action)
	elif hasattr(args, 'command') and hasattr(args, 'action'):
		if hasattr(args, 'scan'):
			if args.scan and args.scan in args.command:
				print("\033[0;34mSCANNING THE IMAGE....\033[0m")
				exec_command(f"trivy image {args.scan} > image.txt 2>&1", os.getcwd())
			elif args.scan and args.scan not in args.command:
				print("\033[1;31mERROR:\033[0m \033[0;31mwrong image name\033[0m")
				return

		str_list = args.command.split(' ')
		# 应用seccomp
		# str_list.insert(3, "--security-opt seccomp=seccomp.json")
		# 启动容器前对挂载位置的检查
		if (str_list.count("-v")):
			idx = str_list.index("-v")
			block_mount = ["/var/run/docker.sock", "/var/log", "/dev/sda1"]
			if str_list[idx + 1].split(':')[0] in block_mount:
				print("\033[1;31mError mount\033[0m")
				return

		container_id = start_container(' '.join(str_list))
		pid = containerid_to_pid(container_id)
		action = args.action
		# print(pid)
		# 启动monitor
		get_dockerinfo()
		start_monitor(pid, action)


if __name__ == '__main__':
	main()

	# c = Choice('Which part do you want to display? (press <esc> to exit) ',
	# 		['Filerecord', 'Procrecord', 'Sysrecord'],
	# 		icon_style=StringStyle(fore=Fore.blue),
	# 		selected_style=StringStyle(fore=Fore.blue))
	# choice = c.get_choice()
	# if choice:
	# 	index, value = choice
	# 	if value == "Filerecord":
	# 		display(FILE_RECORD)
	# 	elif value == "Procrecord":
	# 		display(PROC_RECORD)
	# 	else:
	# 		display(SYS_RECORD)
