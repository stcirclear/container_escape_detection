#!/bin/python
# coding=utf-8

### Container Escape Monitor

import os
import time
import json
import argparse
import subprocess
from multiprocessing import Process
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
			print("ERROR", msg)
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
	print("***** DOCKER INFO GENERATING *****")
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
			dict_data['PATH'] = item.split()[3]
			dict_data['CGROUP'] = item.split()[4]
			dict_data['IPC'] = item.split()[5]
			dict_data['NET'] = item.split()[6]
			dict_data['USER'] = item.split()[7]
			dict_data['UTS'] = item.split()[8]
			json_data['Containers'].append(dict_data)

	with open(CONFIG_FILE) as f:
		config = json.load(f)
		config.update(json_data)

	with open(JSON_OUTPUT, "w") as f:
		f.write(json.dumps(config, indent=4, separators=(',', ': ')))
	print("***** DOCKER INFO GENERATED ******")

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


# 新建容器
def start_container(cmd):
	print("***** STARTING THE CONTAINER *****")
	container_id = exec_command(cmd, os.getcwd())
	print("******* CONTAINER STARTED ********")
	return container_id


# 启动监视器
def start_monitor(pid, action):
	print("****** STARTING THE MONITOR ******")
	# sysrecord
	# cmd = f"sudo ./sysrecord -p {pid}"
	# p1 = Process(target=exec_command, args=(cmd, ))
	# p1.start()

	# fileopen
	cmd = f"sudo ./opensnoop -a {action} -p {pid}"
	p2 = Process(target=exec_command, args=(cmd, ))
	p2.start()

	# procrecord
	# cmd = f"sudo ./procrecord -a {action} -p {pid}"
	# p3 = Process(target=exec_command, args=(cmd, ))
	# p3.start()
	print("******** MONITOR STARTED *********")


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
				print("SCANNING THE IMAGE")
				exec_command(f"./trivy image {args.scan} > image.txt 2>&1", os.getcwd())
			elif args.scan and args.scan not in args.command:
				print("wrong image name")
				return

		str_list = args.command.split(' ')
		# 应用seccomp
		# str_list.insert(3, "--security-opt seccomp=seccomp.json")
		# 启动容器前对挂载位置的检查
		if (str_list.count("-v")):
			idx = str_list.index("-v")
			block_mount = ["/var/run/docker.sock", "/var/log", "/dev/sda1"]
			if str_list[idx + 1].split(':')[0] in block_mount:
				print("Error mount")
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
