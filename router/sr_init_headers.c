#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* Allocate space for a packet to reply */
uint8_t* sr_malloc_packet(unsigned int len, char* message)
{
    uint8_t* re_packet;
    if((re_packet = (uint8_t*) malloc(len)) == NULL) {
        printf("!----! Failed to malloc while replying %s. Dropping.\n", message);
        return NULL;
    }
    return re_packet;
}

/* Initialize the ethernet header of re_packet.
 * The destionation of re_packet is set to be the source of packet.
 * The source of re_packet is set to be the address in the interface.
 * The type REMAINS UNCHANGED, that is, if packet is ARP, re_packet is also ARP.
 * Same for IP. */
void sr_init_ethernet_hdr(uint8_t* re_packet,
                          uint8_t * packet,
                          struct sr_if* interface)
{
    /* Reply packet is similar to request, so copy first. */
    memcpy(re_packet, packet, sizeof(sr_ethernet_hdr_t));

    /* Modify source and destination MAC address of Ethernet header. */
    sr_ethernet_hdr_t* re_ethernet_hdr = (sr_ethernet_hdr_t*) re_packet;
    memcpy(re_ethernet_hdr->ether_dhost, re_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(re_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
}

/* Initialize the ARP header of re_packet.
 * If packet is NULL, then re_packet is initialized to be a broadcast one.
 * Otherwise, the destionation of re_packet is set to be the source of packet;
 * the source of re_packet is set to be the address in the interface;
 * and the operation code is set to be reply (0x0002). */
void sr_init_arp_hdr(uint8_t* re_packet,
                     uint8_t * packet,
                     struct sr_if* interface)
{
    if(!packet) {
        /* TODO Broadcast. */
    } else {
        sr_arp_hdr_t* re_arp_hdr = (sr_arp_hdr_t*) (re_packet + sizeof(sr_ethernet_hdr_t));
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
        memcpy(re_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
        memcpy(re_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
        memcpy(re_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        re_arp_hdr->ar_sip = arp_hdr->ar_tip;
        re_arp_hdr->ar_tip = arp_hdr->ar_sip;
        re_arp_hdr->ar_op = htons(arp_op_reply); /* 0x0002 */
    }
}

void sr_init_ip_hdr(uint8_t* re_packet,
                    uint8_t * packet,
                    struct sr_if* interface,
                    unsigned int ip_protocol)
{
    sr_ip_hdr_t* re_ip_hdr = (sr_ip_hdr_t*) (re_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    re_ip_hdr->ip_ttl = 100;                   /* TODO default 64, sr_solution 100 */
    re_ip_hdr->ip_p = ip_protocol;
    re_ip_hdr->ip_dst = ip_hdr->ip_src;
    re_ip_hdr->ip_src = interface->ip;
    re_ip_hdr->ip_sum = 0;
    re_ip_hdr->ip_sum = cksum(re_ip_hdr, sizeof(sr_ip_hdr_t));
}

void sr_init_icmp_hdr(uint8_t* re_packet, uint8_t * packet,
                      unsigned int type, unsigned int code_or_len)
{
    int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    sr_icmp_hdr_t* re_icmp_hdr = (sr_icmp_hdr_t*)(re_packet + icmp_offset);
    if(type == 0) {
        /* Not only copy header, but also the payload. */
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(re_packet + icmp_offset);
        memcpy(re_icmp_hdr, icmp_hdr, code_or_len);
        re_icmp_hdr->icmp_code = 0;
    } else if(type == 3) {
        re_icmp_hdr->icmp_code = code_or_len;

        /* Copy the header of IP packet and first 8 bytes. */
        sr_icmp_t3_hdr_t* re_icmp_t3_hdr = (sr_icmp_t3_hdr_t*)re_icmp_hdr;
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        memcpy(re_icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        re_icmp_t3_hdr->next_mtu = 1500; /* TODO Should I set it to 1500? */
        re_icmp_t3_hdr->icmp_sum = 0;
        re_icmp_t3_hdr->icmp_sum = cksum(re_icmp_hdr, sizeof(sr_icmp_hdr_t));
    } else if(type == 11) {
        /* TODO to be implemented */
    } else {
        printf("       Cannot create other types of ICMP packets.\n");
        return;
    }
    re_icmp_hdr->icmp_type = type;
    re_icmp_hdr->icmp_sum = 0;
    re_icmp_hdr->icmp_sum = cksum(re_icmp_hdr, sizeof(sr_icmp_hdr_t));
}
