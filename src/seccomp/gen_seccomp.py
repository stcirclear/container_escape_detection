#!/bin/python
# Container SECCOMP GENERATOR

import os
import json
import subprocess

SYSDIG_OUTPUT = "runc.scap"
SYSCALLS = "runc_syscall.txt"
JSON_OUTPUT = "seccomp.json"
CONFIG_FILE = "seccomp_config.json"


# 生成seccomp文件，前提是已经利用sysdig手动生成了runc.scap
# 参考https://bbs.kanxue.com/thread-273495.htm#msg_header_h2_7
def gen_seccomp():
	syscalls = []
	cmd = f"sudo sysdig -p \"%syscall.type\" -r {SYSDIG_OUTPUT} > tmp"
	proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

	cmd = f"sort -u tmp > {SYSCALLS}"
	proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
	with open(SYSCALLS) as f:
		lines = f.readlines()
		# print(lines)
		for line in lines:
			syscalls.append(line.strip())

	with open(CONFIG_FILE) as f:
		config = json.load(f)
		config["syscalls"][0]["names"] = syscalls
		# config.update(json_data)

	with open(JSON_OUTPUT, "w") as f:
		f.write(json.dumps(config, indent=4, separators=(',', ': ')))
	print("SECCOMP FILE GENERATED")


def main():
	gen_seccomp()


if __name__ == '__main__':
	main()
