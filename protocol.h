#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/types.h>
#include <linux/if.h>
#include <linux/llc.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

//#include <sys/time.h>
#include <time.h>

#define IFNAMSIZE1 16
//#define RARP_CACHE       "/home/helen/Desktop/rarp_server/rarp_table"
#define RARP_CACHE       "rarp_table"
#define ARP_STRING_LEN  200
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)
#define SOCKET_ERROR -1

typedef struct rarp_payload
{
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];			/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];			/* target IP address		*/
} rarp_payload;

typedef struct rarp_frame
{
	struct ethhdr  frame_hdr;
	struct arphdr  rarphdr;
	rarp_payload   body;
	unsigned char  trailer[18];
} rarp_frame;

typedef struct rarp_entry
{
unsigned char mac[ETH_ALEN];
unsigned char ip[4];
char ifname[IFNAMSIZE1];
} rarp_entry;

int fprintf_rarp_frame(FILE * f, struct rarp_frame * b);
int isReadable(int sock, int * error, int timeOut);

