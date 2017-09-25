#!/bin/bash

count=$1

for i in $(seq 1 $count)
do
    ./utp-client -h 127.0.0.1 -p 50994 -r client -u &
done
