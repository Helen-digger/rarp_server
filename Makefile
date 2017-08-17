
CC= gcc -std=gnu99
PRF :=$(pwd)
CFLAGS   = -Wall
#SOURC:=$( find $DIR -name '*.c')
all:
	$(CC) -Wall -o rarp_client rarp_client.c
	$(CC) -Wall -o rarp_server rarp_server.c
clean:
	rm -f rarp_client rarp_server *.o *.a *.so 



