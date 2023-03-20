#!/bin/python
# Container Escape Monitor

import os
import sys
import json
import subprocess

TMP_OUTPUT = "output.txt"
JSON_OUTPUT = "dockerinfo.json"
CONFIG_FILE = "config.json"


def exec_command(cmd, cwd=os.getcwd()):
	# print(f"Run cmd '{cmd}' in '{cwd}'")
	try:
		result = subprocess.run(cmd, cwd=cwd, shell=True)
		if result.returncode != 0:
			msg = f"returncode: {result.returncode} cmd: '{result.args}' err:{result.stderr}"
			print("ERROR", msg)
			return False
	except Exception as ex:
		import traceback
		traceback.print_exc()
		return False
	return True


def get_dockerinfo():
	cmd = f"sudo bash dockerpsns.sh > {TMP_OUTPUT}"
	exec_command(cmd, os.getcwd())

	json_data = {"Containers":[]}
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
	print("DOCKER INFO GENERATED")

	os.remove(TMP_OUTPUT)


def start_monitor(pid):
	# syscount
	cmd = f"sudo ./syscount -d 10 -p {pid}"
	exec_command(cmd, os.getcwd())

	# opensnoop, buggy!!!
	cmd = f"sudo ./opensnoop -d 10 -p {pid}"
	exec_command(cmd, os.getcwd())


def main():
	# get docker info
	get_dockerinfo()
	# start monitor：parse json, and use container-id/pid as input
	start_monitor(0)
	# ...


if __name__ == '__main__':
	main()