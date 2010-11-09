#!/usr/bin/python

# Starts many clients simulataneosly to expose race conditions in the logger.

import os, time, signal, sys

if len(sys.argv) < 3:
	print "usage: " + sys.argv[0] + " <numprocs> <numiters>"
	sys.exit()

numprocs = int(sys.argv[1])
numiters = int(sys.argv[2])

for try_i in range(numiters):
	l = []
	for try_j in range(numprocs):
		pid = os.spawnlp(os.P_NOWAIT, '/home/galtekar/src/work/logreplay/remote_package/liblog', 'home/galtekar/src/work/logreplay/remote_package/liblog', 'ls')
		l.append(pid)

	for try_j in range(numprocs):
		pid, exit_code = os.waitpid(l[try_j], 0)
