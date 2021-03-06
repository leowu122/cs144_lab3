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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Internal function declarations */
int is_ip_packet_valid(sr_ip_hdr_t *ip_header, unsigned int len);
int get_ip_ihl_bytes(sr_ip_hdr_t *ip_header);
struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t next_hop_ip);
int should_forward_ip_packet(struct sr_instance *sr, sr_ip_hdr_t *ip_header);
void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *routing_entry);
void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void handle_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface);
					
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
  uint16_t pkttype;

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  pkttype = ethertype(packet);
  if (pkttype == ethertype_ip) {
    handle_ip_packet(sr, packet, len, interface);
  } else if (pkttype == ethertype_arp) {
    handle_arp_packet(sr, packet, len, interface);
  } else {
    fprintf(stderr, "Unsupported ethertype: %d\n", pkttype);
  }
}/* end sr_ForwardPacket */

/**
 * Validates the IP packet by checking the minimum length, checksum, etc. from the given IP header.
 * Returns 1 if the packet is valid, and 0 otherwise.
 */
int is_ip_packet_valid(sr_ip_hdr_t *ip_header, unsigned int len) {
  uint16_t expected_checksum, actual_checksum;
  int ip_ihl_bytes = get_ip_ihl_bytes(ip_header);

  /** 
   * Check the minimum length of the IP packet. An IP packet should at least have
   * the Ethernet header (which includes the MAC header) and the IP header. It should
   * also at least satisfy the IP header length (IHL).
   */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ||
      len < sizeof(sr_ethernet_hdr_t) + ip_ihl_bytes) {
    return 0;
  }

  /* Check that the checksum in the IP header is as expected */
  actual_checksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  expected_checksum = cksum(ip_header, ip_ihl_bytes);
  if (actual_checksum != expected_checksum) {
    return 0;
  }

  /* The IP packet is valid */
  return 1;
}

/**
 * Returns the IHL (Internet Header Length) for the given IP header in bytes.
 */
int get_ip_ihl_bytes(sr_ip_hdr_t *ip_header) {
  /**
   * The ip_hl field is 4 bits, and specifies the length of the IP header
   * in 32-bit words (equivalent to 4-bytes). So the header length is actually
   * ip_hl * 32 bits or ip_hl * 4 bytes.
   */
  return ip_header->ip_hl * 4;
}

/**
 * Finds and returns the entry in the given simple router's routing table that has the
 * longest prefix match with the destination IP address in the given IP header. Returns 0
 * if no entry in the routing table matches the destination IP address.
 */
struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t next_hop_ip) {
  struct sr_rt *longest_prefix_match;
  struct sr_rt *current_entry;
  uint32_t current_entry_prefix;
  uint32_t current_mask;
  uint32_t dest_ip_prefix;

  longest_prefix_match = 0;
  current_entry = sr->routing_table;

  while (current_entry) {
    /**
     * Get the prefixes of the destination IP address in the IP header and the destination IP address
     * of the current routing entry, using the current entry's mask
     */
    current_mask = current_entry->mask.s_addr;
    current_entry_prefix = current_entry->dest.s_addr & current_mask;
    dest_ip_prefix = next_hop_ip & current_mask;

    /**
     * If the prefixes match, and the current mask is longer than the mask of the previous
     * longest_prefix_match, then update the longest_prefix_match
     */
    if (current_entry_prefix == dest_ip_prefix &&
        (!longest_prefix_match || current_mask > longest_prefix_match->mask.s_addr)) {
      longest_prefix_match = current_entry;
    }

    current_entry = current_entry->next;
  }

  return longest_prefix_match;
}

/**
 * Returns 1 if the given simple router instance sr should forward the packet (i.e. the packet
 * is not destined for one of the simple router's IP addresses), and 0 otherwise.
 */
int should_forward_ip_packet(struct sr_instance *sr, sr_ip_hdr_t *ip_header) {
  struct sr_if* current_interface = sr->if_list;

  while (current_interface) {
    if (current_interface->ip == ip_header->ip_dst) {
      /**
       * The packet's destination IP address matches one of the interface's IP in the simple router,
       * so the packet is destined for this router. Therefore it shouldn't be forwarded.
       */
      return 0;
    }

    current_interface = current_interface->next;
  }

  /**
   * The packet's destination IP address does not match any interface IPs, so the packet
   * should be forwarded.
   */
  return 1;
}

/**
 * Forwards the given packet of length len to the next hop address specified in the given routing_entry.
 * The caller of this method must ensure that the TTL is still valid and that there is an entry in the
 * routing table that matches the destination IP address (given by routing_entry).
 */
void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *routing_entry) {
  sr_ethernet_hdr_t *ethernet_header;
  sr_ip_hdr_t *ip_header;
  uint8_t *forward_packet;
  struct sr_if *outgoing_interface;
  struct sr_arpentry *cached_arp;
  int error;

  forward_packet = (uint8_t *) malloc(len);
  if (!forward_packet) {
    perror("forward_ip_packet() error on malloc");
    return;
  }

  /* Make a copy of the original packet */
  memcpy(forward_packet, packet, len);
  ethernet_header = (sr_ethernet_hdr_t *) forward_packet;
  ip_header = (sr_ip_hdr_t *) (forward_packet + sizeof(sr_ethernet_hdr_t));

  /* Recompute the checksum */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, get_ip_ihl_bytes(ip_header));

  /**
   * Get the cached ARP entry for the next-hop IP address, if available.
   * Note that the gateway (gw) in the routing_entry is the next hop IP address.
   * See http://superuser.com/questions/109021/what-does-gateway-in-routing-table-refer-to
   */
  outgoing_interface = sr_get_interface(sr, routing_entry->interface);
  cached_arp = sr_arpcache_lookup(&sr->cache, routing_entry->gw.s_addr);

  if (cached_arp) {
    /**
     * There is a cached ARP entry, so we have the required MAC address.
     * Set up the packet and send it.
     */

    /* Update the Ethernet header */
    memcpy(ethernet_header->ether_dhost, cached_arp->mac, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);

    error = sr_send_packet(sr, forward_packet, len, routing_entry->interface);
    if (error) {
      fprintf(stderr, "Error forwarding IP packet\n");
    }

    free(cached_arp);
  } else {
    /* There is no cached ARP entry, so we need to send an ARP request and add this packet to the queue. */
    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, routing_entry->gw.s_addr, forward_packet, len, routing_entry->interface);
    handle_arpreq(sr, req);
  }

  free(forward_packet);
}

/**
 * Handles the given IP packet of length len received on the passed in interface. The packet is
 * complete with Ethernet header. This method should either forward the packet or, if it's not destined
 * for one of the router's IP addresses, should send ICMP messages back to the sending host.
 */
void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
  sr_ip_hdr_t *ip_header;
  struct sr_rt *longest_prefix_match;

  /* The IP header comes after the Ethernet header */
  ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Sanity-check the packet and drop it if it's invalid */
  if (!is_ip_packet_valid(ip_header, len)) {
    return;
  }

  if (should_forward_ip_packet(sr, ip_header)) {
    longest_prefix_match = find_longest_prefix_match(sr, ip_header->ip_dst);

    if (!longest_prefix_match) {
      /* No matching destination address in the routing table. Send ICMP destination net unreachable */
      send_icmp_packet(icmp_type_3, icmp_code_0, sr, packet, len, interface);
      return;
    }

    ip_header->ip_ttl--;
    if (ip_header->ip_ttl <= 0) {
      /* Send ICMP time exceeded */
      send_icmp_packet(icmp_type_11, icmp_code_0, sr, packet, len, interface);
      return;
    }

    /* Otherwise, it's possible to send the packet */
    forward_ip_packet(sr, packet, len, longest_prefix_match);
  } else {
    /* The packet is sent for one of the interface IP addresses in the simple router */

    if (ip_protocol((uint8_t*)ip_header) == ip_protocol_icmp) {
      /* The packet is an ICMP echo request, so send ICMP echo reply to the sender */
      send_icmp_packet(icmp_type_0, icmp_code_0, sr, packet, len, interface);
    } else {
      /* The packet contains a TCP or UDP payload, so send ICMP port unreachable to the sender */
      send_icmp_packet(icmp_type_3, icmp_code_3, sr, packet, len, interface);
    }
  }
}

/**
 * Validates the ICMP packet. Returns 1 if the packet is valid, and 0 otherwise.
 * Use this before sending the ICMP packet in send_icmp_packet().
 */
int is_icmp_packet_valid(struct sr_instance* sr, uint8_t *packet, unsigned int len)
{
  /* check the length */
  if (len < sizeof(sr_icmp_hdr_t)) {
    fprintf(stderr, "Invalid ICMP header, insufficient length\n");
    return 0;
  }
  return 1;
}


/**
 * Constructs and sends ICMP packets.
 *
 * Handles following ICMP types.
 * 1. Echo Reply (type 0)
 * 2. Destination net unreachable (type 3, code 0)
 * 3. Destination host unreachable (type 3, code 1)
 * 4. Port unreachable (type 3, code 3)
 * 5. Time exceeded (type 11, code 0)
 */
void send_icmp_packet(enum sr_icmp_type type, enum sr_icmp_code code,
        struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    if (!is_icmp_packet_valid(sr, packet, len)) {
      fprintf(stderr, "ICMP packet is not valid\n");
      return;
    }

    struct sr_if *iface = sr_get_interface(sr, interface);
    if (!iface) {
      fprintf(stderr, "Could not get interface!\n");
      return;
    }

    if (type == icmp_type_0) {
        /* ICMP echo request and echo reply seems to use same header */
        uint8_t *new_pkt = (uint8_t *)malloc(len);
        if (!new_pkt) {
            perror("malloc failed");
            return;
        }
        /* must be careful about pointer arithematic! */
        memcpy(new_pkt, packet, len);
        sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)new_pkt;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

        struct sr_rt *rt = find_longest_prefix_match(sr, ip_hdr->ip_src);
        if (!rt) {
          return;
        }

        /* setup ICMP */
        icmp_hdr->icmp_type = icmp_type_0;
        icmp_hdr->icmp_code = icmp_code_0;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

        /* setup IP */
        uint32_t ip_src = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_src;
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* setup Ethernet */
        uint8_t mac_shost[ETHER_ADDR_LEN];
        memcpy(&mac_shost[0], e_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(&e_hdr->ether_shost[0], &e_hdr->ether_dhost[0], ETHER_ADDR_LEN);
        memcpy(&e_hdr->ether_dhost[0], &mac_shost[0], ETHER_ADDR_LEN);

        struct sr_arpentry *cached_arp = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
        if (cached_arp) {
          /**
           * There is a cached ARP entry, so we have the required MAC address.
           * Set up the packet and send it.
           */

          /* Update the Ethernet header */
          memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, cached_arp->mac, ETHER_ADDR_LEN);

          int res = sr_send_packet(sr, new_pkt, len, rt->interface);
          if (res) {
            fprintf(stderr, "Error forwarding IP packet\n");
          }
          free(cached_arp);
          free(new_pkt);
        } else {
          struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, new_pkt, len, rt->interface);
          handle_arpreq(sr, req);
        }

    } else if (type == icmp_type_3) {
        /* ICMP type 3 messages */
        unsigned int newlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t *new_pkt = (uint8_t *)malloc(newlen);
        if (!new_pkt) {
            perror("malloc failed");
            return;
        }
        /* must be careful about pointer arithematic! */
        sr_ethernet_hdr_t *e_orig_hdr = (sr_ethernet_hdr_t *)packet;
        sr_ip_hdr_t *ip_orig_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)new_pkt;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

        struct sr_rt *rt = find_longest_prefix_match(sr, ip_orig_hdr->ip_src);
        if (!rt) {
          return;
        }
	
        /* setup ICMP */
        icmp_hdr->icmp_type = icmp_type_3;
        icmp_hdr->icmp_code = code;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 0;
        memcpy(&icmp_hdr->data[0], ip_orig_hdr, ICMP_DATA_SIZE);
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

        /* setup IP */
        memcpy(ip_hdr, ip_orig_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ip_hdr->ip_src = iface->ip;             /* update ip to current interface's */
        ip_hdr->ip_dst = ip_orig_hdr->ip_src;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, get_ip_ihl_bytes(ip_hdr));

        /* setup Ethernet */
        memcpy(&e_hdr->ether_shost[0], &e_orig_hdr->ether_dhost[0], ETHER_ADDR_LEN);
        memcpy(&e_hdr->ether_dhost[0], &e_orig_hdr->ether_shost[0], ETHER_ADDR_LEN);
        e_hdr->ether_type = htons(ethertype_ip);

        struct sr_arpentry *cached_arp = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
        if (cached_arp) {
          /**
           * There is a cached ARP entry, so we have the required MAC address.
           * Set up the packet and send it.
           */

          /* Update the Ethernet header */
          memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, cached_arp->mac, ETHER_ADDR_LEN);

          printf("SENDING ICMP!\n");
          print_hdrs(new_pkt, newlen);

          int res = sr_send_packet(sr, new_pkt, newlen, rt->interface);
          if (res) {
            fprintf(stderr, "Error forwarding IP packet\n");
          }
          free(cached_arp);
          free(new_pkt);
        } else {
          struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, new_pkt, newlen, rt->interface);
          handle_arpreq(sr, req);
        }

    } else if (type == icmp_type_11) {
        /* ICMP type 11 messages */
        unsigned int newlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
        uint8_t *new_pkt = (uint8_t *)malloc(newlen);
        if (!new_pkt) {
            perror("malloc failed");
            return;
        }
        /* must be careful about pointer arithematic! */
        sr_ethernet_hdr_t *e_orig_hdr = (sr_ethernet_hdr_t *)packet;
        sr_ip_hdr_t *ip_orig_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)new_pkt;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

        struct sr_rt *rt = find_longest_prefix_match(sr, ip_orig_hdr->ip_src);
        if (!rt) {
          return;
        }

        /* setup ICMP */
        icmp_hdr->icmp_type = icmp_type_11;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->unused = 0;
        memcpy(icmp_hdr->data, ip_orig_hdr, ICMP_DATA_SIZE);
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

        /* setup IP */
        memcpy(ip_hdr, ip_orig_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_ttl = INIT_TTL;
        ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
        ip_hdr->ip_src = iface->ip;             /* update ip to current interface's */
        ip_hdr->ip_dst = ip_orig_hdr->ip_src;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, get_ip_ihl_bytes(ip_hdr));

        /* setup Ethernet */
        memcpy(&e_hdr->ether_shost[0], &e_orig_hdr->ether_dhost[0], ETHER_ADDR_LEN);
        memcpy(&e_hdr->ether_dhost[0], &e_orig_hdr->ether_shost[0], ETHER_ADDR_LEN);
        e_hdr->ether_type = htons(ethertype_ip);

        struct sr_arpentry *cached_arp = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
        if (cached_arp) {
          /**
           * There is a cached ARP entry, so we have the required MAC address.
           * Set up the packet and send it.
           */

          /* Update the Ethernet header */
          memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_dhost, cached_arp->mac, ETHER_ADDR_LEN);

          int res = sr_send_packet(sr, new_pkt, newlen, rt->interface);
          if (res) {
            fprintf(stderr, "Error forwarding IP packet\n");
          }
          free(cached_arp);
          free(new_pkt);
        } else {
          struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, new_pkt, newlen, rt->interface);
          handle_arpreq(sr, req);
        }

    } else {
        fprintf(stderr, "Unknown ICMP type: %d\n", type);
    }
}

/**
 * Check if ARP packet is valid. Returns 1 if valid, and 0 otherwise.
 */
int is_arp_packet_valid(uint8_t *packet, unsigned int len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) ) {
    return 0;
  }
  return 1;
}

/**
 * Handles ARP requests.
 * 1. when the router receives an ARP request, it needs to check target IP
 *    with its own and decide whether to send ARP reply or ignore it.
 * 2. when the router forwards a packet, if the target MAC address is not known,
 *    it needs to send an ARP request first to learn the target MAC address.
 */
void handle_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface) {
  if (!is_arp_packet_valid(packet, len)) {
    fprintf(stderr, "Invalid ARP packet of len: %d\n", len);
    return;
  }

  struct sr_if* iface = sr_get_interface(sr, interface);
  if (!iface) {
    fprintf(stderr, "Could not get interface: %s\n", interface);
    return;
  }

  sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t *a_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if (ntohs(e_hdr->ether_type) != ethertype_arp) {
    fprintf(stderr, "Invalid ether_type: %d\n", ntohs(e_hdr->ether_type));
    return;
  }

  unsigned short arp_op = ntohs(a_hdr->ar_op);
  if (arp_op == arp_op_request) {
    /**
     * Packet's target IP address must match the router interface's IP.
     * If not, drop it.
     */
    if (a_hdr->ar_tip != iface->ip) {
      return;
    }

    uint8_t *new_pkt = (uint8_t *)malloc(len);
    if (!new_pkt) {
      fprintf(stderr, "malloc() failed!\n");
      return;
    }

    memcpy(new_pkt, packet, len);
    sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t*)new_pkt;
    sr_arp_hdr_t *new_a_hdr = (sr_arp_hdr_t*)(new_pkt + sizeof(sr_ethernet_hdr_t));
    /* setup ethernet header */
    memcpy(new_e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
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
    free(new_pkt);

  } else if (arp_op == arp_op_reply) {
    /**
     * The ARP reply processing code should move entries from the ARP request
     * queue to the ARP cache:
     *
     * # When servicing an arp reply that gives us an IP->MAC mapping
     * req = arpcache_insert(ip, mac)
     * if req:
     *   send all packets on the req->packets linked list
     *   arpreq_destroy(req)
     */
    struct sr_arpreq *arp_req = sr_arpcache_insert(&(sr->cache),
                                                   a_hdr->ar_sha,
                                                   a_hdr->ar_sip);
    if (arp_req) {
      struct sr_packet *pkt = arp_req->packets;
      sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t*)pkt->buf;
      sr_arp_hdr_t *new_a_hdr = (sr_arp_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));

      while (pkt) {
        /* Update src/dst MAC addresses for the pending packet */
        memcpy(new_e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        memcpy(new_e_hdr->ether_dhost, new_a_hdr->ar_sha, ETHER_ADDR_LEN);

        int res = sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
        if (res != 0) {
          fprintf(stderr, "Error sending a packet\n");
          return;
        }
        pkt = pkt->next;
      }
      sr_arpreq_destroy(&(sr->cache), arp_req);
    }
  } else {
    fprintf(stderr, "Unsupported arp packet: %d\n", arp_op);
  }
}

