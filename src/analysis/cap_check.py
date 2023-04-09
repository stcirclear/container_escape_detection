#!/bin/python
# Capabilities check for processes

# 借助命令："cat /proc/$pid/task/$pid/status | grep Cap"
# 传入两个进程id， pid，ppid，比较pid的权限是否“大于”ppid，是则作出响应
import os
import subprocess
from multiprocessing import Process


# 执行命令行命令
def exec_command(cmd, cwd=os.getcwd()):
	# print(f"Run cmd '{cmd}' in '{cwd}'")
	cap = ""
	try:
		result = subprocess.run(
			cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE)
		if result.returncode != 0:
			msg = f"returncode: {result.returncode} cmd: '{result.args}' err:{result.stderr}"
			print("ERROR", msg)
			return ""
		cap = str(result.stdout, encoding='utf-8')
	except Exception as ex:
		import traceback
		traceback.print_exc()
		return ""
	return cap

# CapInh: 00000000a80425fb
# CapPrm: 00000000a80425fb
# CapEff: 00000000a80425fb
# CapBnd: 00000000a80425fb
# CapAmb: 0000000000000000
# ==================>>>>>>
# 0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
# ==================>>>>>>
# ['cap_chown', 'cap_dac_override', 'cap_fowner', 'cap_fsetid', 'cap_kill', 'cap_setgid', 'cap_setuid', 'cap_setpcap', 'cap_net_bind_service', 'cap_net_raw', 'cap_sys_chroot', 'cap_mknod', 'cap_audit_write', 'cap_setfcap']
# 获得进程pid的进程权限
def get_cap(pid):
	cmd = f"cat /proc/{pid}/task/{pid}/status | grep Cap"
	cap = exec_command(cmd, os.getcwd()).splitlines()[2]
	cap_str = exec_command(f"capsh --decode={cap.split()[1]}")
	cap_list = cap_str.split("=")[1].strip().split(",")
	return cap_list


# 检查p1是否具有p2不具有的权限
def cap_check(p1, p2):
	cap1 = get_cap(p1)
	cap2 = get_cap(p2)
	for item in cap1:
		if item not in cap2:
			# print(item)
			print("WARNING")
			return
	print("OK")


def main():
	cap_check(8662, 1)


if __name__ == '__main__':
	main()
