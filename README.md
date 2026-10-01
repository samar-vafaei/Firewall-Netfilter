Firewall-Netfilter

sudo apt-get install linux-headers-`uname -r`--> make build directory in /lib/modules/$(uname -r) path

make all

make clean


modinfo firewall.ko

lsmod | grep firewall

insmod firewall.ko

rmmod firewall


