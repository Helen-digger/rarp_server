#include "protocol.h"

int fprintf_rarp_frame(FILE * f, struct rarp_frame * b)
{
	fprintf(f, "%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
	// Print Ethernet frame header.
	fprintf(f, "\nEthernet frame header:\n");
	fprintf(f, "Dest   MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	        b->frame_hdr.h_dest[0], b->frame_hdr.h_dest[1],
	        b->frame_hdr.h_dest[2], b->frame_hdr.h_dest[3],
	        b->frame_hdr.h_dest[4], b->frame_hdr.h_dest[5]);
	fprintf(f, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	        b->frame_hdr.h_source[0], b->frame_hdr.h_source[1],
	        b->frame_hdr.h_source[2], b->frame_hdr.h_source[3],
	        b->frame_hdr.h_source[4], b->frame_hdr.h_source[5]);
	// Next is ethernet type code (ETH_P_ARP for ARP).
	// http://www.iana.org/assignments/ethernet-numbers
	fprintf(f, "Eth type:   %04x\n", ntohs(b->frame_hdr.h_proto));

	fprintf(f, "\nEthernet data (RARP header):\n");
	fprintf(f, "Hardware type: %X\n", ntohs (b->rarphdr.ar_hrd));
	fprintf(f, "Protocol type: %X\n", ntohs (b->rarphdr.ar_pro));
	fprintf(f, "lladdr length: %X\n", b->rarphdr.ar_hln);
	fprintf(f, "IPv4 addr len: %X\n", b->rarphdr.ar_pln);
	fprintf(f, "Opcode       : %X\n", ntohs (b->rarphdr.ar_op));

	fprintf(f, "Sender  (MAC) address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	        b->body.ar_sha[0], b->body.ar_sha[1],
	        b->body.ar_sha[2], b->body.ar_sha[3],
	        b->body.ar_sha[4], b->body.ar_sha[5]);
	fprintf(f, "Sender IPv4 addr:      %u.%u.%u.%u\n",
			b->body.ar_sip[0], b->body.ar_sip[1],
			b->body.ar_sip[2], b->body.ar_sip[3]);
	fprintf(f, "Target MAC:            %02x:%02x:%02x:%02x:%02x:%02x\n",
	        b->body.ar_tha[0], b->body.ar_tha[1],
	        b->body.ar_tha[2], b->body.ar_tha[3],
	        b->body.ar_tha[4], b->body.ar_tha[5]);
	fprintf(f, "Target IPv4 addr:      %u.%u.%u.%u\n",
			b->body.ar_tip[0], b->body.ar_tip[1],
			b->body.ar_tip[2], b->body.ar_tip[3]);

	return 0;
}

int isReadable(int sock, int * error, int timeOut)
{
	printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
	// milliseconds
	fd_set socketReadSet;
	FD_ZERO(&socketReadSet);
	FD_SET(sock, &socketReadSet);
	struct timeval tv;
	if (timeOut)
	{
		tv.tv_sec  = timeOut / 1000;
		tv.tv_usec = (timeOut % 1000) * 1000;
	}
	else
	{
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	}

	if (select(sock+1, &socketReadSet, 0, 0, &tv) == SOCKET_ERROR)
	{
		*error = 1;
		return 0;
	}

	*error = 0;
	return FD_ISSET(sock, &socketReadSet) != 0;
}

