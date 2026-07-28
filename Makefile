obj-m += firewall.o
firewall-objs :=  \
	fw_main.o \
	logger.o \
	packet_parser.o \
	rule_engine.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
