#!/usr/bin/env bash

for i in {0..15};
do
    sudo cpufreq-set -c ${i} -f 2400000;
done

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
