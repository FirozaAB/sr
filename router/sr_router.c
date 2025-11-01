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
#include <string.h>
#include <stdlib.h>


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
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* Validate parameters */
  if (len == 0) {
    fprintf(stderr, "Invalid packet length: 0\n");
    return;
  }

  if (len > MAX_PACKET_LEN) {
    fprintf(stderr, "Packet too large: %d bytes\n", len);
    return;
  }

  /* Check minimum ethernet frame size */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Packet too short for Ethernet header\n");
    return;
  }

  /* Parse Ethernet header */
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
  uint16_t ethtype = ntohs(eth_hdr->ether_type);

  /* Handle different ethernet types */
  if (ethtype == ethertype_arp) {
    /* Handle ARP packet */
    sr_handle_arp_packet(sr, packet, len, interface);
  }
  else if (ethtype == ethertype_ip) {
    /* Handle IP packet */
    sr_handle_ip_packet(sr, packet, len, interface);
  }
  else {
    /* Unknown ethernet type, drop packet */
    fprintf(stderr, "Unknown ethernet type: 0x%04x\n", ethtype);
  }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_handle_arp_packet
 * Scope:  Local
 *
 * Handle incoming ARP packets (requests and replies)
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Check minimum ARP packet size */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "ARP packet too short\n");
        return;
    }

    /* Parse ARP header */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Validate ARP protocol fields */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        fprintf(stderr, "ARP: Invalid hardware type %d\n", ntohs(arp_hdr->ar_hrd));
        return;
    }
    
    if (ntohs(arp_hdr->ar_pro) != ethertype_ip) {
        fprintf(stderr, "ARP: Invalid protocol type %d\n", ntohs(arp_hdr->ar_pro));
        return;
    }
    
    if (arp_hdr->ar_hln != ETHER_ADDR_LEN) {
        fprintf(stderr, "ARP: Invalid hardware address length %d\n", arp_hdr->ar_hln);
        return;
    }
    
    if (arp_hdr->ar_pln != 4) {
        fprintf(stderr, "ARP: Invalid protocol address length %d\n", arp_hdr->ar_pln);
        return;
    }

    uint16_t arp_opcode = ntohs(arp_hdr->ar_op);

    /* Handle ARP request or reply */
    if (arp_opcode == arp_op_request) {
        sr_handle_arp_request(sr, packet, len, interface);
    }
    else if (arp_opcode == arp_op_reply) {
        sr_handle_arp_reply(sr, packet, len, interface);
    }
    else {
        fprintf(stderr, "Unknown ARP opcode: %d\n", arp_opcode);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet
 * Scope:  Local
 *
 * Handle incoming IP packets
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Check minimum IP packet size */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "IP packet too short\n");
        return;
    }

    /* Parse IP header */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned int ip_len = len - sizeof(sr_ethernet_hdr_t);

    /* Validate IP packet */
    if (!sr_validate_ip_packet(ip_hdr, ip_len)) {
        fprintf(stderr, "Invalid IP packet\n");
        return;
    }

    /* Check if packet is destined for one of our interfaces */
    struct sr_if* target_iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    if (target_iface) {
        /* Packet is for us - handle based on protocol */
        printf("IP packet destined for router interface\n");
        sr_handle_ip_packet_for_router(sr, packet, len, interface);
    }
    else {
        /* Packet is not for us - forward it */
        printf("Forwarding IP packet\n");
        sr_forward_ip_packet(sr, packet, len, interface);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet_for_router
 * Scope:  Local
 *
 * Handle IP packets destined for the router
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip_packet_for_router(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Parse IP header */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Handle based on IP protocol */
    if (ip_hdr->ip_p == IP_PROTOCOL_ICMP) {
        /* Handle ICMP packet */
        sr_handle_icmp_packet(sr, packet, len, interface);
    }
    else if (ip_hdr->ip_p == IP_PROTOCOL_TCP || ip_hdr->ip_p == IP_PROTOCOL_UDP) {
        /* TCP or UDP packet to router - send ICMP port unreachable */
        sr_send_icmp_unreachable(sr, packet, len, interface, ICMP_CODE_PORT_UNREACHABLE);
    }
    else {
        /* Other protocols - ignore */
        fprintf(stderr, "Unsupported IP protocol: %d\n", ip_hdr->ip_p);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_icmp_packet
 * Scope:  Local
 *
 * Handle ICMP packets destined for the router
 *
 *---------------------------------------------------------------------*/
void sr_handle_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Parse IP header to get variable header length */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;

    /* Check minimum ICMP packet size with variable IP header length */
    if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len + sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "ICMP packet too short\n");
        return;
    }

    /* Calculate ICMP payload length */
    unsigned int icmp_total_len = ntohs(ip_hdr->ip_len) - ip_hdr_len;
    if (icmp_total_len < sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "ICMP payload too short\n");
        return;
    }

    /* Parse ICMP header using variable IP header length */
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

    /* Verify ICMP checksum BEFORE processing type/code */
    uint16_t received_checksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t computed_checksum = cksum(icmp_hdr, icmp_total_len);
    icmp_hdr->icmp_sum = received_checksum;
    
    if (received_checksum != computed_checksum) {
        fprintf(stderr, "ICMP checksum verification failed (got: 0x%04x, expected: 0x%04x)\n", 
                received_checksum, computed_checksum);
        return;
    }

    /* Handle ICMP echo request */
    if (icmp_hdr->icmp_type == ICMP_TYPE_ECHO_REQUEST && icmp_hdr->icmp_code == 0) {
        /* Valid ICMP echo request - send reply */
        sr_send_icmp_echo_reply(sr, packet, len, interface);
    }
    else {
        /* Other ICMP types - ignore */
        fprintf(stderr, "Unsupported ICMP type: %d, code: %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp_echo_reply
 * Scope:  Local
 *
 * Send an ICMP echo reply in response to an ICMP echo request
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Validate length parameter */
    if (len == 0) {
        fprintf(stderr, "Invalid packet length: 0\n");
        return;
    }

    /* Verify minimum packet size for ICMP echo reply */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "Packet too short for ICMP echo reply\n");
        return;
    }

    /* Extract headers from original packet */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Use variable IP header length for ICMP header location */
    unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;
    if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len + sizeof(sr_icmp_echo_hdr_t)) {
        fprintf(stderr, "Packet too short for ICMP echo with IP options\n");
        return;
    }
    
    sr_icmp_echo_hdr_t* icmp_hdr = (sr_icmp_echo_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

    /* Get interface info */
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return;
    }

    /* Create reply packet */
    unsigned int reply_len = len;
    uint8_t* reply_packet = malloc(reply_len);
    if (!reply_packet) {
        fprintf(stderr, "Failed to allocate memory for ICMP echo reply\n");
        return;
    }
    memcpy(reply_packet, packet, reply_len);

    /* Update Ethernet header */
    sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply_packet;
    memcpy(reply_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);

    /* Update IP header */
    sr_ip_hdr_t* reply_ip = (sr_ip_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_ip->ip_src = ip_hdr->ip_dst;
    reply_ip->ip_dst = ip_hdr->ip_src;
    reply_ip->ip_ttl = INIT_TTL;
    reply_ip->ip_sum = 0;
    reply_ip->ip_sum = cksum(reply_ip, ip_hdr_len);

    /* Update ICMP header using variable IP header length - RFC 792 compliant */
    sr_icmp_echo_hdr_t* reply_icmp = (sr_icmp_echo_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
    reply_icmp->icmp_type = ICMP_TYPE_ECHO_REPLY;
    reply_icmp->icmp_code = 0;
    /* Preserve identifier and sequence number from original request - RFC 792 requirement */
    sr_icmp_echo_hdr_t* orig_icmp = (sr_icmp_echo_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
    reply_icmp->icmp_id = orig_icmp->icmp_id;     /* Must preserve identifier */
    reply_icmp->icmp_seq = orig_icmp->icmp_seq;   /* Must preserve sequence number */
    reply_icmp->icmp_sum = 0;
    reply_icmp->icmp_sum = cksum(reply_icmp, len - sizeof(sr_ethernet_hdr_t) - ip_hdr_len);

    /* Send the packet */
    sr_send_packet(sr, reply_packet, reply_len, interface);
    free(reply_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp_unreachable
 * Scope:  Local
 *
 * Send an ICMP destination unreachable message
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp_unreachable(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint8_t icmp_code) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Extract headers from original packet */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* RFC 792 Compliance: Do not send ICMP errors for ICMP error messages */
    if (ip_hdr->ip_p == IP_PROTOCOL_ICMP) {
        /* Check if it's an ICMP error message (types 3, 4, 5, 11, 12) */
        unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;
        if (len >= sizeof(sr_ethernet_hdr_t) + ip_hdr_len + sizeof(sr_icmp_hdr_t)) {
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
            uint8_t icmp_type = icmp_hdr->icmp_type;
            
            /* RFC 792: Don't send ICMP errors for ICMP error messages */
            if (icmp_type == ICMP_TYPE_DEST_UNREACHABLE || 
                icmp_type == 4 ||  /* Source Quench (deprecated) */
                icmp_type == 5 ||  /* Redirect */
                icmp_type == ICMP_TYPE_TIME_EXCEEDED ||
                icmp_type == 12) { /* Parameter Problem */
                fprintf(stderr, "RFC 792: Not sending ICMP error for ICMP error message\n");
                return;
            }
        }
    }
    
    /* RFC 792: Don't send ICMP errors for IP fragments other than first fragment */
    uint16_t ip_off = ntohs(ip_hdr->ip_off);
    if ((ip_off & IP_OFFMASK) != 0) {
        fprintf(stderr, "RFC 792: Not sending ICMP error for IP fragment\n");
        return;
    }

    /* Get interface info */
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return;
    }

    /* Create ICMP error packet */
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* reply_packet = malloc(reply_len);
    if (!reply_packet) {
        fprintf(stderr, "Failed to allocate memory for ICMP unreachable packet\n");
        return;
    }

    /* Fill Ethernet header */
    sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply_packet;
    memcpy(reply_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_ip);

    /* Fill IP header */
    sr_ip_hdr_t* reply_ip = (sr_ip_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_ip->ip_v = 4;
    reply_ip->ip_hl = 5;
    reply_ip->ip_tos = 0;
    reply_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    reply_ip->ip_id = htons(0);     /* Ensure network byte order */
    reply_ip->ip_off = htons(0);    /* Ensure network byte order */
    reply_ip->ip_ttl = INIT_TTL;
    reply_ip->ip_p = IP_PROTOCOL_ICMP;
    reply_ip->ip_src = iface->ip;
    reply_ip->ip_dst = ip_hdr->ip_src;
    reply_ip->ip_sum = 0;
    reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

    /* Fill ICMP header */
    sr_icmp_t3_hdr_t* reply_icmp = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_icmp->icmp_type = ICMP_TYPE_DEST_UNREACHABLE;
    reply_icmp->icmp_code = icmp_code;
    reply_icmp->unused = 0;
    reply_icmp->next_mtu = 0;
    reply_icmp->icmp_sum = 0;
    
    /* RFC 792: Include original IP header + 8 bytes of original data */
    /* Use variable IP header length for proper calculation */
    unsigned int orig_ip_hdr_len = ip_hdr->ip_hl * 4;
    unsigned int available_data = len - sizeof(sr_ethernet_hdr_t);
    
    /* Copy original IP header + 8 bytes of data, but don't exceed ICMP_DATA_SIZE */
    unsigned int min_copy_size = orig_ip_hdr_len + 8;  /* RFC requirement */
    unsigned int copy_size = (available_data < min_copy_size) ? available_data : min_copy_size;
    copy_size = (copy_size > ICMP_DATA_SIZE) ? ICMP_DATA_SIZE : copy_size;
    
    memcpy(reply_icmp->data, ip_hdr, copy_size);
    /* Zero out any remaining bytes if we copied less than ICMP_DATA_SIZE */
    if (copy_size < ICMP_DATA_SIZE) {
        memset(reply_icmp->data + copy_size, 0, ICMP_DATA_SIZE - copy_size);
    }
    
    reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t3_hdr_t));

    /* Send the packet */
    sr_send_packet(sr, reply_packet, reply_len, interface);
    free(reply_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp_time_exceeded
 * Scope:  Local
 *
 * Send an ICMP time exceeded message
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp_time_exceeded(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Extract headers from original packet */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* RFC 792 Compliance: Do not send ICMP errors for ICMP error messages */
    if (ip_hdr->ip_p == IP_PROTOCOL_ICMP) {
        /* Check if it's an ICMP error message (types 3, 4, 5, 11, 12) */
        unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;
        if (len >= sizeof(sr_ethernet_hdr_t) + ip_hdr_len + sizeof(sr_icmp_hdr_t)) {
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
            uint8_t icmp_type = icmp_hdr->icmp_type;
            
            /* RFC 792: Don't send ICMP errors for ICMP error messages */
            if (icmp_type == ICMP_TYPE_DEST_UNREACHABLE || 
                icmp_type == 4 ||  /* Source Quench (deprecated) */
                icmp_type == 5 ||  /* Redirect */
                icmp_type == ICMP_TYPE_TIME_EXCEEDED ||
                icmp_type == 12) { /* Parameter Problem */
                fprintf(stderr, "RFC 792: Not sending ICMP time exceeded for ICMP error message\n");
                return;
            }
        }
    }
    
    /* RFC 792: Don't send ICMP errors for IP fragments other than first fragment */
    uint16_t ip_off = ntohs(ip_hdr->ip_off);
    if ((ip_off & IP_OFFMASK) != 0) {
        fprintf(stderr, "RFC 792: Not sending ICMP time exceeded for IP fragment\n");
        return;
    }

    /* Get interface info */
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return;
    }

    /* Create ICMP error packet */
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t* reply_packet = malloc(reply_len);
    if (!reply_packet) {
        fprintf(stderr, "Failed to allocate memory for ICMP time exceeded packet\n");
        return;
    }

    /* Fill Ethernet header */
    sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply_packet;
    memcpy(reply_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_ip);

    /* Fill IP header */
    sr_ip_hdr_t* reply_ip = (sr_ip_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_ip->ip_v = 4;
    reply_ip->ip_hl = 5;
    reply_ip->ip_tos = 0;
    reply_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    reply_ip->ip_id = htons(0);     /* Ensure network byte order */
    reply_ip->ip_off = htons(0);    /* Ensure network byte order */
    reply_ip->ip_ttl = INIT_TTL;
    reply_ip->ip_p = IP_PROTOCOL_ICMP;
    reply_ip->ip_src = iface->ip;
    reply_ip->ip_dst = ip_hdr->ip_src;
    reply_ip->ip_sum = 0;
    reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

    /* Fill ICMP header */
    sr_icmp_t3_hdr_t* reply_icmp = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_icmp->icmp_type = ICMP_TYPE_TIME_EXCEEDED;
    reply_icmp->icmp_code = ICMP_CODE_TTL_EXCEEDED;
    reply_icmp->unused = 0;
    reply_icmp->next_mtu = 0;
    reply_icmp->icmp_sum = 0;
    
    /* RFC 792: Include original IP header + 8 bytes of original data */
    /* Use variable IP header length for proper calculation */
    unsigned int orig_ip_hdr_len = ip_hdr->ip_hl * 4;
    unsigned int available_data = len - sizeof(sr_ethernet_hdr_t);
    
    /* Copy original IP header + 8 bytes of data, but don't exceed ICMP_DATA_SIZE */
    unsigned int min_copy_size = orig_ip_hdr_len + 8;  /* RFC requirement */
    unsigned int copy_size = (available_data < min_copy_size) ? available_data : min_copy_size;
    copy_size = (copy_size > ICMP_DATA_SIZE) ? ICMP_DATA_SIZE : copy_size;
    
    memcpy(reply_icmp->data, ip_hdr, copy_size);
    /* Zero out any remaining bytes if we copied less than ICMP_DATA_SIZE */
    if (copy_size < ICMP_DATA_SIZE) {
        memset(reply_icmp->data + copy_size, 0, ICMP_DATA_SIZE - copy_size);
    }
    
    reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t3_hdr_t));

    /* Send the packet */
    sr_send_packet(sr, reply_packet, reply_len, interface);
    free(reply_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_validate_ip_packet
 * Scope:  Local
 *
 * Validate an IP packet (minimum length and checksum)
 * Returns 1 if valid, 0 if invalid
 *
 *---------------------------------------------------------------------*/
int sr_validate_ip_packet(sr_ip_hdr_t* ip_hdr, unsigned int len) {
    assert(ip_hdr);

    /* Check minimum length */
    if (len < sizeof(sr_ip_hdr_t)) {
        return 0;
    }

    /* Check IP version */
    if (ip_hdr->ip_v != 4) {
        return 0;
    }

    /* Check header length (must be at least 5 and at most 15) */
    if (ip_hdr->ip_hl < 5 || ip_hdr->ip_hl > 15) {
        return 0;
    }

    /* Check that we have enough data for the IP header length indicated */
    if (len < ip_hdr->ip_hl * 4) {
        return 0;
    }

    /* Check total length field validity */
    uint16_t ip_total_len = ntohs(ip_hdr->ip_len);
    if (ip_total_len < ip_hdr->ip_hl * 4) {
        /* Total length must be at least header length */
        return 0;
    }
    
    if (ip_total_len > len) {
        return 0;
    }

    /* Check TTL */
    if (ip_hdr->ip_ttl == 0) {
        return 0;
    }

    /* Check for invalid source/destination addresses */
    uint32_t src_ip = ntohl(ip_hdr->ip_src);
    uint32_t dst_ip = ntohl(ip_hdr->ip_dst);
    
    /* Check for loopback addresses (127.x.x.x) - not valid in forwarded packets */
    if ((src_ip & 0xFF000000) == 0x7F000000 || (dst_ip & 0xFF000000) == 0x7F000000) {
        return 0;
    }
    
    /* Check for broadcast addresses (255.255.255.255) as source */
    if (src_ip == 0xFFFFFFFF) {
        return 0;
    }
    
    /* Check for multicast source addresses (224.0.0.0/4) */
    if ((src_ip & 0xF0000000) == 0xE0000000) {
        return 0;
    }

    /* Verify checksum */
    uint16_t received_checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t computed_checksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    ip_hdr->ip_sum = received_checksum;

    if (received_checksum != computed_checksum) {
        return 0;
    }

    return 1;
}

/*---------------------------------------------------------------------
 * Method: sr_update_ip_header
 * Scope:  Local
 *
 * Update IP header for forwarding (decrement TTL, recompute checksum)
 *
 *---------------------------------------------------------------------*/
void sr_update_ip_header(sr_ip_hdr_t* ip_hdr) {
    assert(ip_hdr);

    /* Decrement TTL */
    ip_hdr->ip_ttl--;

    /* Recompute checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
}

/*---------------------------------------------------------------------
 * Method: sr_get_interface_by_ip
 * Scope:  Local
 *
 * Find interface by IP address
 * Returns interface if found, NULL otherwise
 *
 *---------------------------------------------------------------------*/
struct sr_if* sr_get_interface_by_ip(struct sr_instance* sr, uint32_t ip) {
    assert(sr);

    /* Validate IP address - reject invalid addresses */
    if (ip == 0) {
        return NULL;  /* 0.0.0.0 is not valid for interface lookup */
    }

    struct sr_if* iface = sr->if_list;
    while (iface) {
        if (iface->ip == ip) {
            return iface;
        }
        iface = iface->next;
    }
    return NULL;
}

/*---------------------------------------------------------------------
 * Method: sr_handle_arp_request
 * Scope:  Local
 *
 * Handle incoming ARP requests
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Extract ARP header */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Check if request is for one of our interfaces */
    struct sr_if* target_iface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
    if (!target_iface) {
        /* Not for us, ignore */
        return;
    }

    /* Get the interface we received this on */
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return;
    }

    /* Create ARP reply */
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* reply_packet = malloc(reply_len);
    if (!reply_packet) {
        fprintf(stderr, "Failed to allocate memory for ARP reply packet\n");
        return;
    }

    /* Fill Ethernet header */
    sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply_packet;
    sr_ethernet_hdr_t* orig_eth = (sr_ethernet_hdr_t*)packet;
    memcpy(reply_eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, target_iface->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_arp);

    /* Fill ARP header */
    sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_arp->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp->ar_pro = htons(ethertype_ip);
    reply_arp->ar_hln = ETHER_ADDR_LEN;
    reply_arp->ar_pln = 4;
    reply_arp->ar_op = htons(arp_op_reply);
    memcpy(reply_arp->ar_sha, target_iface->addr, ETHER_ADDR_LEN);
    reply_arp->ar_sip = target_iface->ip;
    memcpy(reply_arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp->ar_tip = arp_hdr->ar_sip;

    /* Send the reply */
    sr_send_packet(sr, reply_packet, reply_len, interface);
    free(reply_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_handle_arp_reply
 * Scope:  Local
 *
 * Handle incoming ARP replies
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Extract ARP header */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Check if reply is for one of our interfaces */
    struct sr_if* target_iface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
    if (!target_iface) {
        /* Not for us, ignore */
        return;
    }

    /* Insert into ARP cache and get any waiting requests */
    struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

    /* If there were waiting packets, send them now */
    if (req) {
        struct sr_packet* pkt = req->packets;
        while (pkt) {
            /* Update the ethernet destination MAC */
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)pkt->buf;
            memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            
            /* Fix source MAC: Update to the correct outgoing interface MAC */
            struct sr_if* out_iface = sr_get_interface(sr, pkt->iface);
            if (out_iface) {
                memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
            }
            
            /* Send the packet */
            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            pkt = pkt->next;
        }
        
        /* Clean up the request */
        sr_arpreq_destroy(&(sr->cache), req);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_send_arp_request
 * Scope:  Local
 *
 * Send an ARP request for a target IP
 *
 *---------------------------------------------------------------------*/
void sr_send_arp_request(struct sr_instance* sr, uint32_t target_ip, char* interface) {
    assert(sr);
    assert(interface);

    /* Validate interface string length */
    if (strlen(interface) >= sr_IFACE_NAMELEN) {
        fprintf(stderr, "Interface name too long: %s\n", interface);
        return;
    }

    /* Validate target IP address */
    if (target_ip == 0) {
        fprintf(stderr, "Invalid target IP address: 0.0.0.0\n");
        return;
    }

    /* Get interface */
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return;
    }

    /* Create ARP request */
    unsigned int req_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* req_packet = malloc(req_len);
    if (!req_packet) {
        fprintf(stderr, "Failed to allocate memory for ARP request packet\n");
        return;
    }

    /* Fill Ethernet header */
    sr_ethernet_hdr_t* req_eth = (sr_ethernet_hdr_t*)req_packet;
    memset(req_eth->ether_dhost, 0xFF, ETHER_ADDR_LEN); /* Broadcast */
    memcpy(req_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
    req_eth->ether_type = htons(ethertype_arp);

    /* Fill ARP header */
    sr_arp_hdr_t* req_arp = (sr_arp_hdr_t*)(req_packet + sizeof(sr_ethernet_hdr_t));
    req_arp->ar_hrd = htons(arp_hrd_ethernet);
    req_arp->ar_pro = htons(ethertype_ip);
    req_arp->ar_hln = ETHER_ADDR_LEN;
    req_arp->ar_pln = 4;
    req_arp->ar_op = htons(arp_op_request);
    memcpy(req_arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
    req_arp->ar_sip = iface->ip;
    memset(req_arp->ar_tha, 0x00, ETHER_ADDR_LEN); /* Unknown target MAC */
    req_arp->ar_tip = target_ip;

    /* Send the request */
    sr_send_packet(sr, req_packet, req_len, interface);
    free(req_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_longest_prefix_match
 * Scope:  Local
 *
 * Find the best matching route using longest prefix matching
 * Returns routing entry if found, NULL otherwise
 *
 *---------------------------------------------------------------------*/
struct sr_rt* sr_longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip) {
    assert(sr);

    struct sr_rt* rt_walker = sr->routing_table;
    struct sr_rt* best_match = NULL;
    uint32_t longest_mask = 0;

    while (rt_walker) {
        /* Check if destination matches this route */
        /* Both dest_ip and route addresses should be in network byte order for comparison */
        uint32_t dest_ip_net = htonl(dest_ip);
        if ((dest_ip_net & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)) {
            /* Check if this is a longer prefix match */
            /* Convert mask to host byte order for numerical comparison */
            uint32_t current_mask = ntohl(rt_walker->mask.s_addr);
            if (current_mask > longest_mask) {
                longest_mask = current_mask;
                best_match = rt_walker;
            }
        }
        rt_walker = rt_walker->next;
    }

    return best_match;
}

/*---------------------------------------------------------------------
 * Method: sr_forward_ip_packet
 * Scope:  Local
 *
 * Forward an IP packet using the routing table
 *
 *---------------------------------------------------------------------*/
void sr_forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    /* Extract IP header */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Double-check this packet is not destined for one of our interfaces */
    /* This is a critical security check to prevent forwarding loops */
    struct sr_if* dest_iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    if (dest_iface) {
        fprintf(stderr, "ERROR: Attempting to forward packet destined for router interface\n");
        return;
    }

    /* Check TTL */
    if (ip_hdr->ip_ttl <= 1) {
        /* Send ICMP time exceeded */
        sr_send_icmp_time_exceeded(sr, packet, len, interface);
        return;
    }

    /* Find route */
    struct sr_rt* route = sr_longest_prefix_match(sr, ntohl(ip_hdr->ip_dst));
    if (!route) {
        /* No route found, send ICMP destination unreachable */
        sr_send_icmp_unreachable(sr, packet, len, interface, ICMP_CODE_NET_UNREACHABLE);
        return;
    }

    /* Note: Removed split-horizon check - routers MUST be able to forward 
     * packets out the same interface (e.g., default gateway scenarios) */

    /* Update IP header (decrement TTL, recompute checksum) */
    /* Make a copy of the packet since we need to modify it */
    uint8_t* packet_copy = malloc(len);
    if (!packet_copy) {
        fprintf(stderr, "Failed to allocate memory for packet copy\n");
        return;
    }
    memcpy(packet_copy, packet, len);
    
    /* Update IP header in the copy */
    sr_ip_hdr_t* ip_hdr_copy = (sr_ip_hdr_t*)(packet_copy + sizeof(sr_ethernet_hdr_t));
    sr_update_ip_header(ip_hdr_copy);

    /* Determine next hop IP */
    uint32_t next_hop_ip = route->gw.s_addr;
    if (next_hop_ip == 0) {
        /* Direct delivery - destination is next hop */
        next_hop_ip = ip_hdr_copy->ip_dst;
    }

    /* Check ARP cache for next hop MAC */
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
    if (arp_entry) {
        /* ARP entry found, can forward immediately */
        
        /* Update ethernet header */
        sr_ethernet_hdr_t* eth_hdr_copy = (sr_ethernet_hdr_t*)packet_copy;
        struct sr_if* out_iface = sr_get_interface(sr, route->interface);
        if (!out_iface) {
            fprintf(stderr, "Interface %s not found\n", route->interface);
            free(arp_entry);
            free(packet_copy);
            return;
        }
        
        memcpy(eth_hdr_copy->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr_copy->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
        
        /* Send the packet */
        sr_send_packet(sr, packet_copy, len, route->interface);
        free(arp_entry);
        free(packet_copy);
    } else {
        /* ARP entry not found, queue packet - sweep function will handle ARP requests */
        struct sr_arpreq* arp_req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet_copy, len, route->interface);
        if (!arp_req) {
            /* Failed to queue request due to memory allocation failure */
            fprintf(stderr, "Failed to queue ARP request\n");
            free(packet_copy);
            return;
        }
        /* ARP queue makes its own copy - we must free the original */
        free(packet_copy);
    }
}

