#!/bin/bash
#
# dockerpsns - proof of concept for a "docker ps --namespaces".
#
# USAGE: ./dockerpsns.sh
#
# This lists containers, their init PIDs, and namespace IDs. If container
# namespaces equal the host namespace, they are colored red (this can be
# disabled by setting color=0 below).
#
# Copyright 2017 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 10-Apr-2017   Brendan Gregg   Created this.

namespaces="cgroup ipc mnt net pid user uts"

printf "%-14s %-20s %6s %-16s" "CONTAINER-ID" "NAME" "PID" "PATH"
for n in $namespaces; do
	printf " %-10s" $(echo $n | tr a-z A-Z)
done
echo

# print host details
pid=1
read name < /proc/$pid/comm
printf "%-14s %-20.20s %6d %-16.16s" "host" $(hostname) $pid 0 $name
for n in $namespaces; do
	id=$(stat --format="%N" /proc/$pid/ns/$n)
	id=${id#*[}
	id=${id%]*}
	printf " %-10s" "$id"
done
echo

# print containers
for UUID in $(docker ps -q); do
	# docker info:
	pid=$(docker inspect -f '{{.State.Pid}}' $UUID)
	name=$(docker inspect -f '{{.Name}}' $UUID)
	path=$(docker inspect -f '{{.Path}}' $UUID)
	name=${name#/}

	get_ppid=$(ps -elf |awk '$4=='$pid'{print $5}')
    ppid=$get_ppid

	printf "%-14s %-20.20s %6d %6d %-16.16s" $UUID $name $pid $ppid $path

	# namespace info:
	for n in $namespaces; do
		id=$(stat --format="%N" /proc/$pid/ns/$n)
		id=${id#*[}
		id=${id%]*}
		printf " %-10s" "$id"
	done
	echo
	
done