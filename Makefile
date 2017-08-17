
CC= gcc -std=gnu99
PRF :=$(pwd)
CFLAGS   = -Wall
#SOURC:=$( find $DIR -name '*.c')
all:
	$(CC) -Wall -o rarp_client rarp_client.c
clean:
	rm -f rarp_client *.o *.a *.so 



