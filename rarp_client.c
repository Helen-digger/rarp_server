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
	close(fd);
	return 0;
}

/*int set_ip(struct rarp_frame * ans, char * ifname)
{
	printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
	int fd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy( ifr.ifr_name , ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
	inet_pton(AF_INET, ans->body.ar_tip, &addr->sin_addr);
    //inet_pton(AF_INET, ans->body.ar_tip, ifr.ifr_addr.sa_data + 2);
    ioctl(fd, SIOCSIFADDR, &ifr);

	#ifdef ifr_flags
	  # define IRFFLAGS       ifr_flags
	  #else   // Present on kFreeBSD 
	  # define IRFFLAGS       ifr_flagshigh
	  #endif
		//ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	    if (ifr.IRFFLAGS | ~(IFF_UP)) {
	    ifr.IRFFLAGS |= IFF_UP;
	    ioctl(fd, SIOCSIFFLAGS, &ifr);
		}

	close(fd);
	return 0;
}*/

int main (int argc, char **argv)
{
	if (argc < 2) 
	{
		fprintf(stderr, "Usage: %s [IFNAME]\n", argv[0]); return -1;
	}

	int                 sd;
	rarp_frame          buf, ans;
	struct sockaddr_ll  device;
	int                 error, timeOut;

	memset(&buf,     0,    sizeof(rarp_frame));
	memset(&device,  0,    sizeof(struct sockaddr_ll));
	memset(&ans,     0,    sizeof(struct rarp_frame));

	buf.frame_hdr.h_proto = htons(ETH_P_RARP);
	memset(&buf.frame_hdr.h_dest, 0xff, ETH_ALEN);
	if (0 != fill_src_lladdr(&buf, &device, argv[1])) {fprintf(stderr,"'%s': fill_src_lladdr() failed!\n", __func__); return -1;}

	device.sll_family = AF_PACKET;
	device.sll_halen  = ETH_ALEN;
	device.sll_protocol = ETH_P_RARP;

	buf.rarphdr.ar_hrd = htons(ETH_P_802_3);	// Hardware type (16 bits): 1 for ethernet
	buf.rarphdr.ar_pro = htons(ETH_P_IP);		// Protocol type (16 bits): 2048 for IP
	buf.rarphdr.ar_hln = ETH_ALEN;				// Hardware address length (8 bits): 6 bytes for MAC address
	buf.rarphdr.ar_pln = 4;						// Protocol address length (8 bits): 4 bytes for IPv4 address
	buf.rarphdr.ar_op  = htons(ARPOP_RREQUEST);	//rarphdr.opcode = htons (RARPOP_REQUEST);

	if (0 > (sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))) {perror ("socket() failed "); return -1;}

	if (sizeof(buf) != sendto (sd, &buf, sizeof(buf),
	                           0, (struct sockaddr *) &device, sizeof (struct sockaddr_ll)))
	{ perror ("sendto() failed"); return -1;}
	printf("%s 5 %s\n", __func__, (errno ? strerror(errno) : "ok"));
	
	time_t start = time(NULL);
	
	do
	{
		timeOut = 1000; // ms
		if (isReadable(sd, &error, timeOut)) 
		{
			if (0 > recv (sd, &ans, sizeof(struct rarp_frame), 0))
			{
				printf("%s recv %s\n", __func__, (errno ? strerror(errno) : "ok"));
			}
		}
		if (time(NULL) > start + 5)
		{
			close (sd);
			printf("5s timeout!\n");
			return 0;
		}
	} while (!(ans.frame_hdr.h_proto == htons(ETH_P_RARP) &&
		       ans.rarphdr.ar_op == htons(ARPOP_RREPLY)));
	
	fprintf_rarp_frame(stdout, &ans);
	//set_ip(&ans, argv[1]);
	
	close (sd);
	return 0;
}
