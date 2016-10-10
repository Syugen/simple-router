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
#include <string.h>

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

    printf("*** -> Received packet of length %d \n",len);
    /* fill in code here */
    /*hexdump(packet, len);*/
    struct sr_if* sr_interface = sr_get_interface(sr, interface);

    switch(ethertype(packet)) {
        case ethertype_arp: /* hex: 0x0806, dec: 2054 */
            printf("       ARP Packet - ");
            sr_handle_arp_packet(sr, packet, len, sr_interface);
            break;
        case ethertype_ip: /* hex: 0x0800, dec: 2048 */
            printf("       IP Packet - ");
            sr_handle_ip_packet(sr, packet, len, sr_interface);
            break;
        default:
            printf("       Unknown Packet. Dropping.\n");
    }

}/* end sr_ForwardPacket */

/* Handles ARP Packet:
   1) Check Request/Reply?
   2) Store source info in arp table.
   2) If request -> if have the info, send back. if not, don't reply.
   3) If reply -> store the wanted info in arp table.
*/
void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t* packet/* lent */,
        unsigned int len,
        struct sr_if* interface/* lent */)
{
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    switch(htons(arp_hdr->ar_op)) {
        case arp_op_request: /* 0x0001 */
            printf("ARP Request\n");
            sr_handle_arp_request(sr, packet, len, interface);
            break;
        case arp_op_reply: /* 0x0002 */
            printf("ARP Reply\n");
            sr_handle_arp_reply(sr, arp_hdr, interface);
            break;
        default:
            printf("Unknown ARP type. Dropping.\n");
    }
}

void sr_handle_arp_request(struct sr_instance* sr,
                           uint8_t* packet,
                           unsigned int len,
                           struct sr_if* interface)
{
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    printf("       Asking for MAC with IP address ");
    printf_addr_ip_int(htonl(arp_hdr->ar_tip));

    /* Check the interface list if I am the target. If not, don't reply. */
    if(!sr_if_contains_ip(interface, htonl(arp_hdr->ar_tip))) {
        printf("       I don't have that IP address. Can't help you. Dropping.\n");
        return;
    }

    /* TODO need to cache it if it has not been cached!!!!!!!!!!!!!!!!!! */

    /* re_packet: the ARP reply message */
    int headers_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* re_packet;
    if((re_packet = (uint8_t*) malloc(headers_len)) == NULL) {
        printf("!----! Failed to malloc while replying ARP request. Dropping.\n");
        return;
    }

    /* Reply packet is similar to request, so copy first. */
    memcpy(re_packet, packet, len);

    /* Modify source and destination MAC address of Ethernet header. */
    sr_ethernet_hdr_t* re_ethernet_hdr = (sr_ethernet_hdr_t*) re_packet;
    memcpy(re_ethernet_hdr->ether_dhost, re_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(re_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    /* Modify source and destination MAC and IP address of ARP header as well as
       the operation code (0x0002 for reply). */
    sr_arp_hdr_t* re_arp_hdr = (sr_arp_hdr_t*) (re_packet + sizeof(sr_ethernet_hdr_t));
    memcpy(re_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    memcpy(re_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    re_arp_hdr->ar_sip = arp_hdr->ar_tip;
    re_arp_hdr->ar_tip = arp_hdr->ar_sip;
    re_arp_hdr->ar_op = htons(arp_op_reply); /* 0x0002 */

    /* Send the reply message. */
    printf(".\n       I have that IP. My MAC is ");
    printf_addr_eth(re_arp_hdr->ar_sha);
    printf(".\n       Replying the ARP request... ");
    sr_send_packet(sr, re_packet, headers_len, interface->name);
    printf("Done.\n");
    free(re_packet);
}

void sr_handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_if* interface)
{
    printf("Replying!!!!!!!\n");
}

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t* packet/* lent */,
        unsigned int len,
        struct sr_if* interface/* lent */)
{
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* IP Packet for me */
    if(sr_if_contains_ip(interface, htonl(ip_hdr->ip_dst))) {
        switch(ip_hdr->ip_p) {
            case ip_protocol_icmp:
                printf("ICMP for me - ");
                sr_handle_icmp_reply(sr, packet, len, interface);
                break;
            default:
                printf("I can only handle ICMP for me (No TCP, UDP). Dropping.\n");
        }
    } else {  /* Not for me */
        printf("ICMP/TCP/UDP/... for ");
        printf_addr_ip_int(htonl(ip_hdr->ip_dst));
        printf(". Forwarding... (Not implemented)\n");
        /* TODO */
    }
}

void sr_handle_icmp_reply(struct sr_instance* sr,
                          uint8_t* packet, unsigned int len,
                          struct sr_if* interface)
{
    /* Only handle the ICMP echo request (type == 8, code == 0). */
    int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + icmp_offset);
    if(icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
        printf("ICMP Echo Request.\n");

        uint8_t* re_packet;
        if((re_packet = (uint8_t*) malloc(len)) == NULL) {
            printf("!----! Failed to malloc while replying ICMP echo request. Dropping.\n");
            return;
        }

        /* Almost everything including the payload is the same as the original
           packet except for something in header. So copy first*/
        memcpy(re_packet, packet, len);

        sr_ethernet_hdr_t* re_ethernet_hdr = (sr_ethernet_hdr_t*) re_packet;
        memcpy(re_ethernet_hdr->ether_dhost, re_ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(re_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

        sr_ip_hdr_t* re_ip_hdr = (sr_ip_hdr_t*) (re_packet + sizeof(sr_ethernet_hdr_t));
        re_ip_hdr->ip_ttl = 100;                   /* TODO default 64, sr_solution 100 */
        re_ip_hdr->ip_dst = re_ip_hdr->ip_src;
        re_ip_hdr->ip_src = interface->ip;
        re_ip_hdr->ip_sum = 0;
        re_ip_hdr->ip_sum = cksum(re_ip_hdr, sizeof(sr_ip_hdr_t));

        sr_icmp_hdr_t* re_icmp_hdr = (sr_icmp_hdr_t*)(re_packet + icmp_offset);
        re_icmp_hdr->icmp_type = re_icmp_hdr->icmp_code = 0;
        re_icmp_hdr->icmp_sum = 0;
        re_icmp_hdr->icmp_sum = cksum(re_icmp_hdr, sizeof(sr_icmp_hdr_t));

        printf("       Replying the ICMP echo request... ");
        sr_send_packet(sr, re_packet, len, interface->name);
        printf("Done.\n");
        free(re_packet);
    } else {
        printf("\n       I can only handle ICMP echo request. Dropping.\n");
    }
}
