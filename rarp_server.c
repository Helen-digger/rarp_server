#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset()

#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806, ETH_P_ALL = 0x0003
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

// Define an struct for ARP header
typedef struct _rarp_hdr rarp_hdr;
struct _rarp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

#define ARPOP_RREQUEST  3   /* RARP request     */
#define ARPOP_RREPLY  4   /* RARP reply     */
#define RARP_HDRLEN 28  // RARP header length

// Function prototypes

int main (int argc, char **argv)
{
  int i, sd, status;
  unsigned char ether_frame[14];
  rarp_hdr *rarphdr;
  unsigned char rarpframe[sizeof(ether_frame) + sizeof(struct _rarp_hdr)];
  memset(rarpframe, 0, sizeof(rarpframe));
  memcpy(rarpframe, ether_frame, sizeof(ether_frame));
  memcpy(rarpframe + sizeof(ether_frame), &rarphdr, RARP_HDRLEN * sizeof (unsigned char));
printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }
printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
  // Listen for incoming ethernet frame from socket sd.
  // We expect an ARP ethernet frame of the form:
  //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
  //     + ethernet data (ARP header) (28 bytes)
  // Keep at it until we get an ARP reply.
  rarphdr = (rarp_hdr *) (ether_frame + 6 + 6 + 2);
  
    if ((status = recv (sd, rarpframe,
                            sizeof(rarpframe),
                            0)) < 0) {
      if (errno == EINTR) {
        memset (ether_frame, 0, 14 * sizeof (unsigned char));
        
      } else {
        perror ("recv() failed:");
        exit (EXIT_FAILURE);
      }
  }
  printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
  close (sd);
printf("%s %s\n", __func__, (errno ? strerror(errno) : "ok"));
  // Print out contents of received ethernet frame.
  printf ("\nEthernet frame header:\n");
  printf ("Destination MAC (this node): ");
  for (i=0; i<5; i++) {
    printf ("%02x:", ether_frame[i]);
  }
  printf ("%02x\n", ether_frame[5]);
  printf ("Source MAC: ");
  for (i=0; i<5; i++) {
    printf ("%02x:", ether_frame[i+6]);
  }
  printf ("%02x\n", ether_frame[11]);
  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  printf ("Ethernet type code (2054 = ARP): %u\n", ((ether_frame[12]) << 8) + ether_frame[13]);
  printf ("\nEthernet data (ARP header):\n");
  printf ("Hardware type (1 = ethernet (10 Mb)): %u\n", ntohs (rarphdr->htype));
  printf ("Protocol type (2048 for IPv4 addresses): %u\n", ntohs (rarphdr->ptype));
  printf ("Hardware (MAC) address length (bytes): %u\n", rarphdr->hlen);
  printf ("Protocol (IPv4) address length (bytes): %u\n", rarphdr->plen);
  printf ("Opcode (2 = ARP reply): %u\n", ntohs (rarphdr->opcode));
  printf ("Sender hardware (MAC) address: ");
  for (i=0; i<5; i++) {
    printf ("%02x:", rarphdr->sender_mac[i]);
  }
  printf ("%02x\n", rarphdr->sender_mac[5]);
  printf ("Sender protocol (IPv4) address: %u.%u.%u.%u\n",
    rarphdr->sender_ip[0], rarphdr->sender_ip[1], rarphdr->sender_ip[2], rarphdr->sender_ip[3]);
  printf ("Target (this node) hardware (MAC) address: ");
  for (i=0; i<5; i++) {
    printf ("%02x:", rarphdr->target_mac[i]);
  }
  printf ("%02x\n", rarphdr->target_mac[5]);
  printf ("Target (this node) protocol (IPv4) address: %u.%u.%u.%u\n",
    rarphdr->target_ip[0], rarphdr->target_ip[1], rarphdr->target_ip[2], rarphdr->target_ip[3]);

  return (EXIT_SUCCESS);
}

