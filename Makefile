obj-m := block_driver.o
block_driver-objs := my_block_driver_alloc_space.o my_block_driver.o data_process.o
PWD = $(shell pwd)

all:
	make -c $(KDIR) M=$(PWD) modules
	
clean:
	rm -rf *.o