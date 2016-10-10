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
            printf("       ARP Packet: ");
            sr_handle_arp_packet(sr, packet, len, sr_interface);
            break;
        case ethertype_ip: /* hex: 0x0800, dec: 2048 */
            printf("       IP Packet: ");
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
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    switch(htons(arp_hdr->ar_op)) {
        case arp_op_request: /* 0x0001 */
            printf("ARP Request\n");
            sr_handle_arp_request(sr, ethernet_hdr, arp_hdr, interface);
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
                           sr_ethernet_hdr_t* ethernet_hdr,
                           sr_arp_hdr_t* arp_hdr,
                           struct sr_if* interface)
{
    printf("       Asking for MAC with IP ");
    printf_addr_ip_int(htonl(arp_hdr->ar_tip));

    /* Check if I am the target. If not, don't reply. */
    if(interface->ip != arp_hdr->ar_tip) { /* No need to htonl. */
        printf("       I'm not with that IP. My IP is ");
        printf_addr_ip_int(htonl(interface->ip));
        printf(". Dropping.\n");
        return;
    }

    /* re_packet: the ARP reply message */
    int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* re_packet = (uint8_t*) malloc(len);

    /* Set the ethernet header of re_packet. Everything is the same as
       ethernet_hdr except the MAC address of source and destination. */
    sr_ethernet_hdr_t* re_ethernet_hdr = (sr_ethernet_hdr_t*) re_packet;
    memcpy(re_ethernet_hdr, ethernet_hdr, sizeof(sr_ethernet_hdr_t));
    memcpy(re_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(re_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    /* Set the ARP header of re_packet. Everything is the same as arp_hdr
       except the MAC and IP address of source and destination as well as
       the operation code (0x0002 for reply). */
    sr_arp_hdr_t* re_arp_hdr = (sr_arp_hdr_t*) (re_packet + sizeof(sr_ethernet_hdr_t));
    memcpy(re_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
    memcpy(re_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    memcpy(re_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    re_arp_hdr->ar_sip = arp_hdr->ar_tip;
    re_arp_hdr->ar_tip = arp_hdr->ar_sip;
    re_arp_hdr->ar_op = htons(arp_op_reply); /* 0x0002 */

    printf(".\n       I'm with that IP. My MAC is ");
    printf_addr_eth(re_arp_hdr->ar_sha);
    printf(".\n       Replying the ARP request...\n");
    sr_send_packet(sr, re_packet, len, interface->name);
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
/*    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) packet;
*/    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* For me */
    if(htonl(ip_hdr->ip_dst) == htonl(interface->ip)) { /* It's OK if no convertion. */
        switch(ip_hdr->ip_p) {
            case ip_protocol_icmp:
                printf("Yeah！ ICMP for me!\n");
                break;
            default:
                printf("I can only handle ICMP :(\n");
        }
    } else {  /* Not for me */
        printf("Not for me. OK...\n");
    }
}
