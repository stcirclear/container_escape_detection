#!/bin/bash
mkdir -p host
mount /dev/sda1 /host
sleep 20
chroot /host
