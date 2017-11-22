CC=gcc
DEPS = aes-ni.h aes-ni-2.h

#%.o: %.c $(DEPS)
#	$(CC) -c -o $@ $< $(CFLAGS)

encrypt: enc-main.o aes-ni.o 
	gcc -o encrypt enc-main.o aes-ni.o

decrypt: dec-main.o aes-ni.o 
	gcc -o decrypt dec-main.o aes-ni.o
	
lrf-encrypt: enc-main-2.o aes-ni-2.o aes-ni-asm.o
	gcc -g -o lrf-encrypt enc-main-2.o aes-ni-2.o aes-ni-asm.o
