#!/usr/bin/python

import sys
import os
import subprocess, re
import curses.wrapper

if len(sys.argv) < 2:
	print "usage: " + sys.argv[0] + " <binary>"
	sys.exit()

filename = sys.argv[1]

def get_lib_deps ( filename ):
	"""Returns a list of libraries that FILENAME depends on."""

	args = ['ldd']
	args.append(filename)

	child = subprocess.Popen(args, stdin=subprocess.PIPE,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE);

	exit_code = child.wait()
	if exit_code != 0:
		print "ldd failed."
		sys.exit()
	else:
		ldd_out = child.stdout.readlines()

	lib_list = []
	for line in ldd_out:
		match = re.compile(r"(\s+(.+)\s+=>)?\s+([/\w\.\-]+) \(.+\)").search(line)
		if match != None:
			lib_list.append(match.group(3))

	return lib_list


def get_asm_dump ( filename ):
	"""Gets an instruction dump of FILENAME"""

	args = ['objdump', '-S']
	args.append(filename)

	child = subprocess.Popen(args, stdin=subprocess.PIPE,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE);

#exit_code = child.wait()
#	if exit_code != 0:
#print "objdump failed."
#		sys.exit()

	return child.stdout.readlines()



def contains_direct_syscalls( line_list ):
	"""Does the string contain any systems calls (e.g, int $0x80,
	   sysenter, sysexit, rdtsc, etc.) """

	int80_count = 0
	sysenter_count = 0
	sysexit_count = 0
	rdtsc_count = 0
	for line in line_list:
		int80_res = re.compile(r"int\s+\$0x80").search(line)
		sysenter_res = re.compile(r"sysenter").search(line)
		sysexit_res = re.compile(r"sysexit").search(line)
		rdtsc_res = re.compile(r"rdtsc").search(line)

		if int80_res != None:
			int80_count = int80_count + 1
		if sysenter_res != None:
			sysenter_count = sysenter_count + 1
		if sysexit_res != None:
			sysexit_count = sysexit_count + 1
		if rdtsc_res != None:
			rdtsc_count = rdtsc_count + 1

	return [int80_count, sysenter_count, sysexit_count, rdtsc_count]

def check_for_syscalls( filename ):
	"""Checks FILENAME and any dependencies for direct syscalls"""

	libdeps = get_lib_deps(filename)
	libdeps.append(filename)

	for libname in libdeps:

		count_list = contains_direct_syscalls( get_asm_dump( libname ) )

#if num_syscalls != 0:
		print '%26s has '%(libname) + " " + str(count_list)



def main():
	check_for_syscalls(filename)

main()
