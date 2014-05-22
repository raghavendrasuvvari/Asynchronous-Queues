obj-m += sys_xjob.o
ccflags-y  += -DEXTRA_CREDIT
all: xhw3 xhw3_modify xjob

xhw3: xhw3.c
	#gcc -Wall -Werror -I/lib/modules/$(shell uname -r)/build/arch/x86/include xhw3.c -o xhw3
	gcc -Wall -Werror xhw3.c -o xhw3

xhw3_modify: xhw3_modify.c
	gcc -Wall -Werror xhw3_modify.c -o xhw3_modify


xjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3
	rm -f xhw3_modify
