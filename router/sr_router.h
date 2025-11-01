/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* ICMP Types */
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

/* ICMP Codes */
#define ICMP_CODE_NET_UNREACHABLE 0
#define ICMP_CODE_HOST_UNREACHABLE 1
#define ICMP_CODE_PORT_UNREACHABLE 3
#define ICMP_CODE_TTL_EXCEEDED 0

/* Protocol Constants */
#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17
#define ARP_REQUEST_INTERVAL 1.0
#define ARP_MAX_ATTEMPTS 5
#define MAX_PACKET_LEN 65535  /* Maximum IP packet size */

/* ICMP Echo Request/Reply Structure - RFC 792 compliant */
struct sr_icmp_echo_hdr {
    uint8_t icmp_type;      /* ICMP message type */
    uint8_t icmp_code;      /* ICMP message code */
    uint16_t icmp_sum;      /* ICMP checksum */
    uint16_t icmp_id;       /* ICMP identifier */
    uint16_t icmp_seq;      /* ICMP sequence number */
} __attribute__ ((packed));
typedef struct sr_icmp_echo_hdr sr_icmp_echo_hdr_t;

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- Packet handling functions -- */
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_handle_ip_packet_for_router(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_handle_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

/* -- Helper functions for ICMP -- */
void sr_send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_send_icmp_unreachable(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint8_t icmp_code);
void sr_send_icmp_time_exceeded(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

/* -- Helper functions for IP -- */
int sr_validate_ip_packet(sr_ip_hdr_t* ip_hdr, unsigned int len);
void sr_update_ip_header(sr_ip_hdr_t* ip_hdr);
struct sr_if* sr_get_interface_by_ip(struct sr_instance* sr, uint32_t ip);

/* -- Helper functions for ARP -- */
void sr_handle_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_handle_arp_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_send_arp_request(struct sr_instance* sr, uint32_t target_ip, char* interface);

/* -- Helper functions for routing -- */
struct sr_rt* sr_longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip);
void sr_forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

/* -- if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
