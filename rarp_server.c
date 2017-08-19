#include "protocol.h"

unsigned char get_ip_from_arp(rarp_frame *a)
{

	rarp_entry rarp_addr;
	FILE *arpCache = fopen(RARP_CACHE, "r");
	if (!arpCache)
	{
		perror("Arp Cache: Failed to open file \"" RARP_CACHE "\"");
		return 1;
	}
	while (11 == fscanf(arpCache,"%02x:%02x:%02x:%02x:%02x:%02x %u.%u.%u.%u %s",
		   &rarp_addr.mac[0], &rarp_addr.mac[1], &rarp_addr.mac[2],
		   &rarp_addr.mac[3], &rarp_addr.mac[4], &rarp_addr.mac[5],
		   &rarp_addr.ip[0], &rarp_addr.ip[1], &rarp_addr.ip[2], &rarp_addr.ip[3], &rarp_addr.ifname))
	{
			printf("%02x:%02x:%02x:%02x:%02x:%02x %u.%u.%u.%u %s\n", 
				rarp_addr.mac[0], rarp_addr.mac[1], rarp_addr.mac[2],
				rarp_addr.mac[3], rarp_addr.mac[4], rarp_addr.mac[5],
				rarp_addr.ip[0], rarp_addr.ip[1], rarp_addr.ip[2], rarp_addr.ip[3], rarp_addr.ifname);

			if (0 == memcmp(a->body.ar_tha, rarp_addr.mac, ETH_ALEN))
			{
				memcpy(a->body.ar_tip, rarp_addr.ip, 4);
				printf("IPv4 addr:	  %u.%u.%u.%u\n",
					a->body.ar_tip[0], a->body.ar_tip[1],
					a->body.ar_tip[2], a->body.ar_tip[3]);
				break;
			}
	}
	fclose(arpCache);
	return 0;
}

int build_ans(rarp_frame * a, rarp_frame * b, struct sockaddr_ll * dev, char *ifname)
{
	int fd;
	struct ifreq ifr;
	memset(a, 0, sizeof(rarp_frame));
	memset(&ifr, 0, sizeof(ifr));

	fd = socket( AF_INET , SOCK_DGRAM , 0 );

	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);
	ioctl( fd , SIOCGIFADDR , &ifr );
	memcpy(a->body.ar_sip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
	printf("%s 2 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	memset(&ifr, 0, sizeof(ifr));
	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(dev->sll_addr,         ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(a->frame_hdr.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(a->body.ar_sha,        ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(a->body.ar_tha,        b->body.ar_sha, ETH_ALEN);

	memset(&ifr, 0, sizeof(ifr));
	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);
	ioctl(fd, SIOCGIFINDEX, &ifr);
	dev->sll_ifindex = ifr.ifr_ifindex;
	close(fd);
	get_ip_from_arp(a);
	memcpy(a->frame_hdr.h_dest, b->frame_hdr.h_source,ETH_ALEN);
	a->frame_hdr.h_proto = htons(ETH_P_RARP);
	dev->sll_family = AF_PACKET;
	dev->sll_halen  = ETH_ALEN;
	dev->sll_protocol = ETH_P_RARP;

	a->rarphdr.ar_hrd = htons(ETH_P_802_3);		// Hardware type (16 bits): 1 for ethernet
	a->rarphdr.ar_pro = htons(ETH_P_IP);		// Protocol type (16 bits): 2048 for IP
	a->rarphdr.ar_hln = ETH_ALEN;				// Hardware address length (8 bits): 6 bytes for MAC address
	a->rarphdr.ar_pln = 4;						// Protocol address length (8 bits): 4 bytes for IPv4 address
	a->rarphdr.ar_op  = htons(ARPOP_RREPLY);	//rarphdr.opcode = htons (RARPOP_REQUEST);

	fprintf_rarp_frame(stdout, a);
	return 0;
}


int main (int argc, char **argv)
{
	struct rarp_frame buf, ans;
	struct sockaddr_ll device;
	int sd;

	if (argc < 2) {fprintf(stderr, "Usage: %s [IFNAME]\n", argv[0]); return -1;}

	memset(&buf, 0, sizeof(struct rarp_frame));

	if (0 > (sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))) {perror ("socket() failed "); exit (EXIT_FAILURE);} //ETH_P_RARP

	for(;;)
	{
		do
		{
			if (0 > recv (sd, &buf, sizeof(struct rarp_frame), 0))
			{
				printf("%s recv %s\n", __func__, (errno ? strerror(errno) : "ok"));
			}
		} while (!(buf.frame_hdr.h_proto == htons(ETH_P_RARP) &&
			       buf.rarphdr.ar_op == htons(ARPOP_RREQUEST)));
		fprintf_rarp_frame(stdout, &buf);

		build_ans(&ans, &buf, &device, argv[1]);

		if (sizeof(ans) != sendto (sd, &ans, sizeof(rarp_frame),
		                           0, (struct sockaddr *) &device, sizeof (struct sockaddr_ll)))
		{ perror ("sendto() failed"); return -1;}
		memset(&buf, 0, sizeof(struct rarp_frame));
	}
	close (sd);

	return (EXIT_SUCCESS);
}
