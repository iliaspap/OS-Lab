	#!/usr/bin/python

	import sys
	import os

	lines = sys.stdin.readlines()

	for line in lines:
		temp = line.split(":")
		if (temp[0] == 'create') and not(os.path.exists("/sys/fs/cgroup/cpu/monitor/" + temp[3].rstrip())):
			os.makedirs("/sys/fs/cgroup/cpu/monitor/" + temp[3].rstrip())
		elif temp[0] == 'remove':
			os.rmdir("/sys/fs/cgroup/cpu/monitor/" + temp[3].rstrip())
		elif temp[0] == 'add': 
			os.system('echo ' + temp[4].strip() + ' > /sys/fs/cgroup/cpu/monitor/' + temp[3]+ '/tasks')
		elif temp[0] == 'set_limit':
			os.system('echo ' + temp[5].strip() + ' > /sys/fs/cgroup/cpu/monitor/' + temp[3]+ '/cpu.shares')
		else:
			print "Uknown Command"

