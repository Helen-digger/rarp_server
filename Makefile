
CC= gcc -std=gnu99
PRF :=$(pwd)
CFLAGS   = -Wall
#SOURC:=$( find $DIR -name '*.c')
all:
	$(CC) -Wall -o rarp_client rarp_client.c protocol.c
	$(CC) -Wall -o rarp_server rarp_server.c protocol.c
clean:
	rm -f rarp_client rarp_server parse_arp *.o *.a *.so 



