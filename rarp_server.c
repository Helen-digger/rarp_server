#include "protocol.h"


int get_ip_from_arp(unsigned char * mac)
{
    FILE *arpCache = fopen(ARP_CACHE, "r");
    if (!arpCache)
    {
        perror("Arp Cache: Failed to open file \"" ARP_CACHE "\"");
        return 1;
    }

    /* Ignore the first line, which contains the header */
    char header[ARP_BUFFER_LEN];
    if (!fgets(header, sizeof(header), arpCache))
    {
        return 1;
    }

    char ipAddr[ARP_BUFFER_LEN], hwAddr[ARP_BUFFER_LEN], device[ARP_BUFFER_LEN], state[ARP_BUFFER_LEN];
    int count = 0;
    while (4 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, state, hwAddr, device))
    {	
        printf("%03d: Mac Address of [%s]\t on [%s] is \"%s\"  State: %s\n",
                ++count, ipAddr, device, hwAddr, state);
    }

    
    fclose(arpCache);
    return 0;
}

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

int main (int argc, char **argv)
{
	struct rarp_frame buf;

	memset(&buf, 0, sizeof(struct rarp_frame));
	int sd;

printf("%s 1 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	if (0 > (sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)))) {perror ("socket() failed "); exit (EXIT_FAILURE);} //ETH_P_RARP

printf("%s 2 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	if (0 > recv (sd, &buf, sizeof(struct rarp_frame), 0))
	{
		printf("%s recv %s\n", __func__, (errno ? strerror(errno) : "ok"));
	}
	
	printf("%s 3 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	close (sd);

	fprintf_rarp_frame(stdout, &buf);

	printf("%s 5 %s\n", __func__, (errno ? strerror(errno) : "ok"));

	return (EXIT_SUCCESS);
}
