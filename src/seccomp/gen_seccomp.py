#!/bin/python
# Container SECCOMP GENERATOR

import json

JSON_OUTPUT = "seccomp.json"
CONFIG_FILE = "seccomp_config.json"


def get_syscalls():
	pass


# 生成seccomp文件
def gen_seccomp():
	# should get syscalls from monitor
	syscalls = ["clone", "close", "prctl", "getpid", "write", "unshare",
				"read", "exit_group", "procexit", "setsid", "setuid", "setgid"]
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
