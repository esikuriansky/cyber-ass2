

KBUILD_CFLAGS += -w

obj-m += kblocker.o

all:
	make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -g -o hasher nlHasher.c -lssl -lcrypto
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(OBJS)	
