#!/bin/python
# Container Escape Monitor

import os
import time
import json
import argparse
import subprocess
from multiprocessing import Process

TMP_OUTPUT = "output.txt"
JSON_OUTPUT = "dockerinfo.json"
CONFIG_FILE = "dockerinfo_config.json"


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
# def get_dockerinfo():
# 	cmd = f"sudo bash dockerpsns.sh > {TMP_OUTPUT}"
# 	exec_command(cmd, os.getcwd())

# 	json_data = {"Containers": []}
# 	with open(TMP_OUTPUT, "r") as f:
# 		data = f.readlines()
# 		for item in data[1:]:
# 			# json
# 			dict_data = {}
# 			dict_data['CONTAINER-ID'] = item.split()[0]
# 			dict_data['NAME'] = item.split()[1]
# 			dict_data['PID'] = int(item.split()[2])
# 			dict_data['PATH'] = item.split()[3]
# 			dict_data['CGROUP'] = item.split()[4]
# 			dict_data['IPC'] = item.split()[5]
# 			dict_data['NET'] = item.split()[6]
# 			dict_data['USER'] = item.split()[7]
# 			dict_data['UTS'] = item.split()[8]
# 			json_data['Containers'].append(dict_data)

# 	with open(CONFIG_FILE) as f:
# 		config = json.load(f)
# 		config.update(json_data)

# 	with open(JSON_OUTPUT, "w") as f:
# 		f.write(json.dumps(config, indent=4, separators=(',', ': ')))
# 	print("DOCKER INFO GENERATED")

# 	os.remove(TMP_OUTPUT)


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
	# p = Process(target=exec_command, args=(cmd, ))
	# p.start()
	container_id = exec_command(cmd, os.getcwd())
	return container_id


# 启动监视器
def start_monitor(pid):
	# syscount
	cmd = f"sudo ./syscount -d 10 -p {pid} > syscount.txt"
	p1 = Process(target=exec_command, args=(cmd, ))
	p1.start()

	# exec, buggy!!! write when ctrl+c, this is not correct
	cmd = f"sudo ./execsnoop -n ls > execsnoop.txt"
	p2 = Process(target=exec_command, args=(cmd, ))
	p2.start()

	# opensnoop, buggy!!! can't trace the open in container
	cmd = f"sudo ./opensnoop -d 10 -p {pid} > opensnoop.txt"
	p3 = Process(target=exec_command, args=(cmd, ))
	p3.start()

# TODO: 添加是否进行实时拦截or告警的参数
def parse_args():
	parser = argparse.ArgumentParser(description='Container Escape Monitor.')

	# 添加参数
	subparsers = parser.add_subparsers(help='sub-command help')
	parser_a = subparsers.add_parser('monitor', help='monitor mode')
	parser_a.add_argument('-p', '--pid',  action='store',
						  help='process id', required=True)
	parser_b = subparsers.add_parser('run', help='run mode')
	parser_b.add_argument('-c', '--command', action='store',
						  help='container run command', required=True)

	# 解析参数
	args = parser.parse_args()
	return args


def main():
	# get docker info
	# get_dockerinfo()
	pid = 0
	args = parse_args()
	if hasattr(args, 'pid'):
		pid = int(args.pid)
		print(pid)
		# 启动monitor
		# start_monitor(pid)
	else:
		# 需要假设 **待运行容器的seccomp.json文件已经生成好**,
		# 在docker run后添加“--security-opt seccomp=seccomp.json”
		str_list = args.command.split(' ')
		# str_list.insert(3, "--security-opt seccomp=seccomp.json")
		container_id = start_container(' '.join(str_list))
		# TODO: 给1s的容器创建时间
		# time.sleep(1)
		pid = containerid_to_pid(container_id)
		print(pid)
		# 启动monitor
		# start_monitor(pid)


if __name__ == '__main__':
	main()
