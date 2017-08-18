#include "protocol.h"

int fill_src_lladdr(struct rarp_frame * buf, struct sockaddr_ll * dev, char * ifname)
{
	printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
	int fd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	memcpy(dev->sll_addr,           ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(buf->frame_hdr.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(buf->body.ar_sha,        ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(buf->body.ar_tha,        ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	ioctl(fd, SIOCGIFINDEX, &ifr);
	dev->sll_ifindex = ifr.ifr_ifindex;
	//if ((dev->sll_ifindex = if_nametoindex (ifname)) == 0) {perror ("if_nametoindex() failed"); return -1;}

	close(fd);
	return 0;
}

int main (int argc, char **argv)
{
	if (argc < 2) {fprintf(stderr, "Usage: %s [IFNAME]\n", argv[0]); return -1;}

	int                 sd;
	rarp_frame          buf;
	struct sockaddr_ll  device;

	memset(&buf,     0,    sizeof(rarp_frame));
	memset(&device,  0,    sizeof (struct sockaddr_ll));

	printf("%s 2 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	buf.frame_hdr.h_proto = htons(ETH_P_RARP);
	memset(&buf.frame_hdr.h_dest, 0xff, ETH_ALEN);
	if (0 != fill_src_lladdr(&buf, &device, argv[1])) {fprintf(stderr,"'%s': fill_src_lladdr() failed!\n", __func__); return -1;}

	printf("%s 3 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	device.sll_family = AF_PACKET;
	device.sll_halen  = ETH_ALEN;
	device.sll_protocol = ETH_P_RARP;

	buf.rarphdr.ar_hrd = htons(ETH_P_802_3);	// Hardware type (16 bits): 1 for ethernet
	buf.rarphdr.ar_pro = htons(ETH_P_IP);		// Protocol type (16 bits): 2048 for IP
	buf.rarphdr.ar_hln = ETH_ALEN;				// Hardware address length (8 bits): 6 bytes for MAC address
	buf.rarphdr.ar_pln = 4;						// Protocol address length (8 bits): 4 bytes for IPv4 address
	buf.rarphdr.ar_op  = htons(ARPOP_RREQUEST);	//rarphdr.opcode = htons (RARPOP_REQUEST);

	if (0 > (sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))) {perror ("socket() failed "); return -1;}

	printf("%s 4 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	if (sizeof(buf) != sendto (sd, &buf, sizeof(buf),
	                           0, (struct sockaddr *) &device, sizeof (struct sockaddr_ll)))
	{ perror ("sendto() failed"); return -1;}

	printf("%s 5 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	close (sd);
	return 0;
}
