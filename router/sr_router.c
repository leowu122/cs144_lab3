/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  uint16_t ethertype;

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  ethertype = ethertype(packet);
  if (ethertype == ethertype_ip) {
    handle_ip_packet(sr, packet, len, interface);
  } else if (ethertype == ethertype_arp) {
    handle_arp_packet(sr, packet, len, interface);
  } else {
    fprintf(stderr, "Unsupported ethertype: %d\n", ethertype);
  }
}/* end sr_ForwardPacket */

/**
 * TODO: Laura
 *
 * Validates the IP packet (minimum length, checksum, etc.). Returns 1 if the packet is valid, and 0 otherwise.
 * Use this in handle_ip_packet();
 */
int is_ip_packet_valid(struct sr_instance* sr, uint8_t *packet, unsigned int len) {

}

/**
 * TODO: Laura
 */
void handle_ip_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface) {

}

/**
 * TODO: Leo
 *
 * Validates the ICMP packet (minimum length, checksum, etc.). Returns 1 if the packet is valid, and 0 otherwise.
 * Use this before sending the ICMP packet in send_icmp_packet().
 */
int is_icmp_packet_valid(struct sr_instance* sr, uint8_t *packet, unsigned int len) 
{
    assert(sr);
	assert(packet);
	
	minlength += sizeof(sr_icmp_hdr_t);
    
	/* check the length*/
	if (len < minlength) 
	{
		fprintf(stderr, "Invalid ICMP header, insufficient length\n");
		return 0;
    } 
	else 
	{
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	}
	
	uint16_t received_cksum = icmp_hdr->icmp_sum;
	icmp_hdr->icmp_sum = 0;
	
	uint16_t expected_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
	
	/* check the checksum*/
	if (expected_cksum != received_cksum) 
	{
		fprintf(stderr, "Invalid ICMP header, insufficient checksum\n");
		return 0;
	}
	
	/* check echo request*/
	if (icmp_hdr->icmp_type != ICMP_ECHO_REQUEST)
	{
		fprintf(stderr, "Invalid ICMP header, not echo request\n");
		return 0;
	}
	/* check echo reply*/
	if (icmp_hdr->icmp_code != ICMP_ECHO_REPLY)
	{
		fprintf(stderr, "Invalid ICMP header, not echo reply\n");
		return 0;
	}
	
	return 1;
}

/**
 * TODO: Leo
 */
void send_icmp_packet(uint8_t icmp_type, uint8_t icmp_code, struct sr_instance* sr,
                      uint8_t *packet, unsigned int len, char *interface) {

}

/**
 * TODO: Sukwon
 *
 * Validates the ARP packet (minimum length, etc.). Returns 1 if the packet is valid, and 0 otherwise.
 * Use this in handle_arp_packet();
 */
int is_arp_packet_valid(struct sr_instance* sr, uint8_t *packet, unsigned int len) {

}

/**
 * TODO: Sukwon
 *
 * soh: handles ARP requests.
 * 1. when the router receives an ARP request, it needs to check target IP
 *    with its own and decide whether to send ARP reply or ignore it.
 * 2. when the router forwards a packet, if the target MAC address is not known,
 *    it needs to send an ARP request first to learn the target MAC address.
 */
void handle_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface) {
  struct sr_if* iface = sr_get_interface(sr, interface);
  // TODO: Why not use the typedef sr_ethernet_hdr_t and sr_arp_hdr_t?
  struct sr_ethernet_hdr* e_hdr = 0;
  struct sr_arp_hdr*       a_hdr = 0;

  // TODO: perhaps move this to is_arp_packet_valid()?
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr) )
  { return; }

  assert(iface);

  e_hdr = (struct sr_ethernet_hdr*)packet;
  a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

  if ( (e_hdr->ether_type == htons(ethertype_arp)) &&
       (a_hdr->ar_op == htons(arp_op_request)) ) {
    /* construct ARP reply and send */
    struct sr_ethernet_hdr* new_e_hdr = 0;
    struct sr_arp_hdr* new_a_hdr = 0;
    uint8_t *new_pkt = (uint8_t *)malloc(len);
    if (!new_pkt) {
      perror("malloc failed");
      return;
    }
    memcpy(new_pkt, packet, len);
    new_e_hdr = (struct sr_ethernet_hdr*)new_pkt;
    new_a_hdr = (struct sr_arp_hdr*)(new_pkt + sizeof(struct sr_ethernet_hdr));
    /* setup ethernet header */
    memcpy(new_e_hdr->ether_dhost, a_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(new_e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    new_e_hdr->ether_type = htons(ethertype_arp);
    /* setup arp header */
    new_a_hdr->ar_op = htons(arp_op_reply);
    memcpy(new_a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    new_a_hdr->ar_sip = iface->ip;
    memcpy(new_a_hdr->ar_tha, a_hdr->ar_sha, ETHER_ADDR_LEN);
    new_a_hdr->ar_tip = a_hdr->ar_sip;

    /* send! */
    int res = sr_send_packet(sr, new_pkt, len, interface);
    if (res != 0) {
      fprintf(stderr, "Error sending ARP reply\n");
      return;
    }
  }
}
