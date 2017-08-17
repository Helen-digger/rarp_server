#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
//#include <linux/if_arp.h>
#include <arpa/inet.h>	//htons etc
#include <net/if.h>	 //ifreq
#include <unistd.h>	 //close
#include <netinet/in.h>
#include <netinet/in.h>
#include <errno.h>
//#define IFNAMSIZ 16

#define MAC_LENGTH 6
#define IPV4_LENGTH 4

#define RARP_HDRLEN 28  // RARP header length
#define ETH_HDRLEN 14   // Ethernet header length
//#define	IP_MAXPACKET	65535		/* maximum packet size */


/*
	ar$hrd (hardware address space) -	16 bits
	ar$pro (protocol address space) -	16 bits
	ar$hln (hardware address length) - 8 bits
	ar$pln (protocol address length) - 8 bits
	ar$op	(opcode) - 16 bits
	ar$sha (source hardware address) - n bytes,
	where n is from the ar$hln field.
	ar$spa (source protocol address) - m bytes,
	where m is from the ar$pln field.
	ar$tha (target hardware address) - n bytes
	ar$tpa (target protocol address) - m bytes
*/
// Define a struct for ARP header
typedef struct _rarp_hdr rarp_header;

struct _rarp_hdr {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_len;
	unsigned char protocol_len;
	unsigned short opcode;
	unsigned char sender_mac[MAC_LENGTH];
	unsigned char sender_ip[IPV4_LENGTH];
	unsigned char target_mac[MAC_LENGTH];
	unsigned char target_ip[IPV4_LENGTH];
};

void usage()
{	printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
	fprintf(stderr, "Usage: [ interface]\n");
	exit(1);
}

int MAC_address(unsigned char * mac, struct sockaddr_ll * dev, char * ifname)
{	printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
	int fd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	memset(mac, 0, MAC_LENGTH);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);

	ioctl(fd, SIOCGIFHWADDR, &ifr); 

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	if ((dev->sll_ifindex = if_nametoindex (ifname)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		return -1;
	}

	close(fd);
	return 0;
}

int main (int argc, char **argv)
{
	printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));

	/*char *ifname, *target, *src_ip;*/
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s [IFNAME]\n", argv[0]);
		return -1;
	}
	
	int /*i, status,*/ frame_length, sd, bytes;
	rarp_header rarphdr;
	unsigned char src_mac[6], dst_mac[6], ether_frame[14];
	unsigned char rarpframe[sizeof(ether_frame) + sizeof(struct _rarp_hdr)];
	struct sockaddr_ll device;
	memset (&device, 0, sizeof (struct sockaddr_ll));

	printf("%s 1 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	// Set destination MAC address: broadcast address
	memset (dst_mac, 0xff, 6 * sizeof (unsigned char));

	printf("%s 2 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	if (0!=MAC_address(src_mac, &device, argv[1]))
	{
		fprintf(stderr,"'%s': Mac() failed!\n", __func__);
		return -1;
	}

	printf("%s 3 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, 6 * sizeof (unsigned char));
	device.sll_halen    = 6;

	printf("%s 4 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	rarphdr.hardware_type = htons (1);			// Hardware type (16 bits): 1 for ethernet
	rarphdr.protocol_type = htons (ETH_P_IP);	// Protocol type (16 bits): 2048 for IP
	rarphdr.hardware_len = 6;					// Hardware address length (8 bits): 6 bytes for MAC address
	rarphdr.protocol_len = 4;					// Protocol address length (8 bits): 4 bytes for IPv4 address
	rarphdr.opcode = 3;							//rarphdr.opcode = htons (RARPOP_REQUEST);

	memcpy (rarphdr.sender_mac, src_mac, 6 * sizeof (unsigned char));
	memset (rarphdr.target_mac, 0, 6 * sizeof (unsigned char));		// Target hardware address (48 bits): zero, since we don't know it yet.

	printf("%s 5 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
	frame_length = 6 + 6 + 2 + RARP_HDRLEN;

	// Destination and Source MAC addresses
	memcpy (ether_frame, dst_mac, 6 * sizeof (unsigned char));
	memcpy (ether_frame + 6, src_mac, 6 * sizeof (unsigned char));
	// Next is ethernet type code (ETH_P_ARP for ARP).
	// http://www.iana.org/assignments/ethernet-numbers
	ether_frame[12] = ETH_P_RARP / 256;
	ether_frame[13] = ETH_P_RARP % 256;

	printf("%s 6 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	memset(rarpframe, 0, sizeof(rarpframe));
	memcpy(rarpframe, ether_frame, sizeof(ether_frame));
	memcpy(rarpframe + sizeof(ether_frame), &rarphdr, RARP_HDRLEN * sizeof (unsigned char));

	// Submit request for a raw socket descriptor.
	if (0 > (sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))) {
		perror ("socket() failed ");
		return -1;
	}

	printf("%s 7 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	// Send ethernet frame to socket.
	if (0 >= (bytes = sendto (sd,
	                          rarpframe,
	                          sizeof(rarpframe),
	                          0,
	                          (struct sockaddr *) &device,
	                          sizeof (struct sockaddr_ll))))
	{
		perror ("sendto() failed");
		return -1;
	}

	printf("%s 8 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	// Close socket descriptor.
	close (sd);
	return 0;

}