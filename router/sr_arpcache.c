#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* Forward declarations */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
void handle_arpreq_no_destroy(struct sr_instance *sr, struct sr_arpreq *req);

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/

/*---------------------------------------------------------------------
 * Method: handle_arpreq
 * Scope:  Local
 *
 * Handle an individual ARP request - send ARP request or timeout
 *
 *---------------------------------------------------------------------*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);
    
    /* Check if we need to send/resend ARP request */
    if (req->sent == 0 || difftime(now, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
            /* Send ICMP host unreachable to source addr of all pkts waiting on this request */
            struct sr_packet *pkt = req->packets;
            while (pkt) {
                /* Extract IP header to get source address */
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt->buf + sizeof(sr_ethernet_hdr_t));
                
                /* Send ICMP host unreachable */
                sr_send_icmp_unreachable(sr, pkt->buf, pkt->len, pkt->iface, ICMP_CODE_HOST_UNREACHABLE);
                
                pkt = pkt->next;
            }
            
            /* Destroy the request */
            sr_arpreq_destroy(&(sr->cache), req);
        } else {
            /* Send ARP request - use interface from first packet if available */
            if (req->packets && req->packets->iface) {
                sr_send_arp_request(sr, req->ip, req->packets->iface);
                req->sent = now;
                req->times_sent++;
            } else {
                /* If no packets in queue, we can't determine interface, destroy request */
                sr_arpreq_destroy(&(sr->cache), req);
            }
        }
    }
}

/*
 * Version of handle_arpreq that doesn't call sr_arpreq_destroy
 * Used by sr_arpcache_sweepreqs which manages request lifecycle
 */
void handle_arpreq_no_destroy(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);
    
    if (req->times_sent >= 5) {
        /* Send ICMP host unreachable to source addr of all pkts waiting on this request */
        struct sr_packet *pkt = req->packets;
        while (pkt) {
            /* Extract IP header to get source address */
            sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt->buf + sizeof(sr_ethernet_hdr_t));
            
            /* Send ICMP host unreachable */
            sr_send_icmp_unreachable(sr, pkt->buf, pkt->len, pkt->iface, ICMP_CODE_HOST_UNREACHABLE);
            
            pkt = pkt->next;
        }
        
        /* Free the request manually since we removed it from cache already */
        struct sr_packet *pkt_to_free = req->packets;
        while (pkt_to_free) {
            struct sr_packet *next_pkt = pkt_to_free->next;
            if (pkt_to_free->buf) free(pkt_to_free->buf);
            if (pkt_to_free->iface) free(pkt_to_free->iface);
            free(pkt_to_free);
            pkt_to_free = next_pkt;
        }
        free(req);
    } else {
        /* Send ARP request - use interface from first packet if available */
        if (req->packets && req->packets->iface) {
            sr_send_arp_request(sr, req->ip, req->packets->iface);
            req->sent = now;
            req->times_sent++;
            
            /* Put request back in cache for future processing */
            pthread_mutex_lock(&(sr->cache.lock));
            req->next = sr->cache.requests;
            sr->cache.requests = req;
            pthread_mutex_unlock(&(sr->cache.lock));
        } else {
            /* If no packets in queue, we can't determine interface, free the request */
            struct sr_packet *pkt_to_free = req->packets;
            while (pkt_to_free) {
                struct sr_packet *next_pkt = pkt_to_free->next;
                if (pkt_to_free->buf) free(pkt_to_free->buf);
                if (pkt_to_free->iface) free(pkt_to_free->iface);
                free(pkt_to_free);
                pkt_to_free = next_pkt;
            }
            free(req);
        }
    }
}

void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* 
     * DEADLOCK AVOIDANCE STRATEGY:
     * Instead of holding the lock while calling handle_arpreq (which may call sr_arpreq_destroy),
     * we collect all requests that need processing first, then process them without holding the lock.
     * This avoids the double-locking issue in sr_arpreq_destroy.
     */
    
    pthread_mutex_lock(&(sr->cache.lock));
    
    /* First pass: collect all requests that need processing into a temporary list */
    struct sr_arpreq *req_list = NULL;
    struct sr_arpreq *req = sr->cache.requests;
    
    while (req) {
        struct sr_arpreq *next = req->next;
        time_t now = time(NULL);
        
        /* Check if this request needs processing */
        if (req->sent == 0 || difftime(now, req->sent) > 1.0) {
            /* Remove from cache list and add to our processing list */
            if (req == sr->cache.requests) {
                sr->cache.requests = next;
            } else {
                /* Find previous node to update its next pointer */
                struct sr_arpreq *prev = sr->cache.requests;
                while (prev && prev->next != req) {
                    prev = prev->next;
                }
                if (prev) {
                    prev->next = next;
                }
            }
            
            /* Add to our processing list */
            req->next = req_list;
            req_list = req;
        }
        
        req = next;
    }
    
    pthread_mutex_unlock(&(sr->cache.lock));
    
    /* Second pass: process all collected requests without holding the cache lock */
    req = req_list;
    while (req) {
        struct sr_arpreq *next = req->next;
        handle_arpreq_no_destroy(sr, req);
        req = next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        if (!req) {
            fprintf(stderr, "Failed to allocate memory for ARP request\n");
            pthread_mutex_unlock(&(cache->lock));
            return NULL;
        }
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        if (!new_pkt) {
            fprintf(stderr, "Failed to allocate memory for ARP packet\n");
            pthread_mutex_unlock(&(cache->lock));
            return req;
        }
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        if (!new_pkt->buf) {
            fprintf(stderr, "Failed to allocate memory for ARP packet buffer\n");
            free(new_pkt);
            pthread_mutex_unlock(&(cache->lock));
            return req;
        }
        
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        if (!new_pkt->iface) {
            fprintf(stderr, "Failed to allocate memory for ARP packet interface\n");
            free(new_pkt->buf);
            free(new_pkt);
            pthread_mutex_unlock(&(cache->lock));
            return req;
        }
        
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->iface[sr_IFACE_NAMELEN - 1] = '\0';  /* Ensure null termination */
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

