#!/bin/bash

make
rmmod virtio_crypto.ko
insmod virtio_crypto.ko
./crypto_dev_nodes.sh
