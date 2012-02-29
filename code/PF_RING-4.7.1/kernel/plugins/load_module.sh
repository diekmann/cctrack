#!/bin/bash
make

#sudo insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=1 K_D_dividend=1 K_P_dividend=1463 inertia=3 sample_limit=1500 buffer_target_fill_level=4 warn_min_sample_rate=2000 && read -n 1 -s && sudo rmmod cctrack_plugin

#sudo insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=1 K_D_dividend=1 K_P_dividend=1463 inertia=10 sample_limit=40000 buffer_target_fill_level=4 warn_min_sample_rate=2000 && read -n 1 -s && sudo rmmod cctrack_plugin

sudo insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=10 K_D_dividend=1828 K_P_dividend=14263 inertia=8 sample_limit=15000 buffer_target_fill_level=4 warn_min_sample_rate=20000 && read -n 1 -s && sudo rmmod cctrack_plugin

#sudo insmod ./cctrack_plugin.ko ht_size=1342177280 K_I_dividend=0 K_D_dividend=1000000 K_P_dividend=0 inertia=0 sample_limit=5000 buffer_target_fill_level=4 warn_min_sample_rate=2000 && read -n 1 -s && sudo rmmod cctrack_plugin

