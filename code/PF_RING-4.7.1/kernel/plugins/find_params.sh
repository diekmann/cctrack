#!/bin/bash
make

# insmod ./cctrack_plugin.ko ht_size=134217728 K_I_dividend=100 K_D_dividend=1000 K_P_dividend=14630 inertia=3 sample_limit=15000 buffer_target_fill_level=10 && read -n 1 -s 
#insmod ./cctrack_plugin.ko ht_size=134217728 K_I_dividend=10 K_D_dividend=10 K_P_dividend=500000 inertia=3 sample_limit=50000 buffer_target_fill_level=4

rmmod cctrack_plugin
rmmod pf_ring
rmmod ixgbe 

modprobe pf_ring transparent_mode=2 min_num_slots=100000
modprobe ixgbe RSS=2
sleep 1
ifconfig mon0 up

#insmod ./cctrack_plugin.ko ht_size=134217728 K_I_dividend=100 K_D_dividend=10 K_P_dividend=50000 inertia=3 sample_limit=50000 buffer_target_fill_level=4
#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=100000 K_D_dividend=100 K_D_divisor=100 K_P_dividend=100000000 inertia=8 sample_limit=50000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=2000
#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=1 K_I_divisor=1073 K_D_dividend=150000 K_P_dividend=3333333 inertia=8 sample_limit=1100000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=65
#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=3125 K_I_divisor=65536 K_D_dividend=1 K_D_divisor=100 K_P_dividend=100000000 inertia=10 sample_limit=2000000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=2000 

#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=3125 K_I_divisor=65536 K_D_dividend=335544 K_D_divisor=-1 K_P_dividend=100000000 inertia=8 sample_limit=50000 buffer_target_fill_level=4 inertia_pkt=1

# && read -n 1 -s 
#&& sudo rmmod cctrack_plugin

# Snort: 
#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=1 K_I_divisor=1073 K_D_dividend=1500 K_P_dividend=3333333 inertia=8 sample_limit=1100000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=65

#tstat
#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=2 K_I_divisor=1000 K_D_dividend=15000 K_P_dividend=12333333 inertia=6 sample_limit=1100000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=65

# test
#insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=1 K_I_divisor=1000 K_D_dividend=1500 K_P_dividend=12333333 inertia=6 sample_limit=1000000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=65

insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=0 K_I_divisor=1 K_D_dividend=0 K_P_dividend=1 inertia=6 sample_limit=100000 buffer_target_fill_level=4 inertia_pkt=1 warn_min_sample_rate=65
