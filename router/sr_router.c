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

    switch (ethertype(packet)) {
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
    switch (htons(arp_hdr->ar_op)) {
        case arp_op_request: /* 0x0001 */
            printf("ARP Request\n");
            sr_handle_arp_request(sr, packet, len, interface);
            break;
        case arp_op_reply: /* 0x0002 */
            printf("ARP Reply\n");
            sr_handle_arp_reply(sr, arp_hdr, interface);
            break;
        default:
            printf("Not ARP Request/Reply (type unchecked). Dropping.\n");
    }
}

void sr_handle_arp_request(struct sr_instance* sr,
                           uint8_t* packet,
                           unsigned int len,
                           struct sr_if* interface)
{
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    printf("       It is asking for MAC with IP address ");
    printf_addr_ip_int(htonl(arp_hdr->ar_tip));

    /* Check the interface list if I am the target. If not, don't reply. */
    if (!sr_if_contains_ip(sr, arp_hdr->ar_tip)) {
        printf("       I don't have that IP address. Can't help you. Dropping.\n");
        return;
    }

    /* Different from some source on the Internet, in sr_solution, even if the
    router is the target, it does not cache it. So this line is commented. */
    /*sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);*/

    /* Create reply packet and initialize headers. */
    uint8_t* re_packet = sr_malloc_packet(len, "ARP reply");
    if (!re_packet) return;
    sr_init_ethernet_hdr(re_packet, packet, interface);
    sr_init_arp_hdr(re_packet, packet, interface);

    /* Send the reply message. */
    printf(".\n       I have that IP. Sending ARP reply... ");
    sr_send_packet(sr, re_packet, len, interface->name);
    printf("Done.\n");
    free(re_packet);
}

void sr_handle_arp_reply(struct sr_instance* sr,
                         sr_arp_hdr_t* arp_hdr,
                         struct sr_if* interface)
{
    printf("       Received response\n");
    /* TODO If this ARP is not for me. Would this happen? */

    /* This is following the instruction in sr_arpcache.h line 39-47. */
    struct sr_arpreq *req;
    req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

    if (req) {
        /* List of packets. Also means the current packet during iteration. */
        struct sr_packet *packets;
        for (packets = req->packets; packets; packets = packets->next) {
            printf("       Time to send this packet.\n");

            uint8_t* packet = packets->buf;
            unsigned int len = packets->len;
            sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) packet;
            memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
            printf("       Sending IP packet to next hop... ");
            sr_send_packet(sr, packet, len, interface->name);
            printf("Done.\n");
        }
        sr_arpreq_destroy(&sr->cache, req);
    }
}

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t* packet/* lent */,
        unsigned int len,
        struct sr_if* interface/* lent */)
{
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* IP Packet for me */
    struct sr_if* dest_interface = sr_if_contains_ip(sr, ip_hdr->ip_dst);
    if (dest_interface) {
        uint32_t dst_ip = dest_interface->ip;
        switch (ip_hdr->ip_p) {
            case ip_protocol_icmp:
                printf("ICMP for me - ");
                sr_handle_ip_icmp_me(sr, packet, len, interface, dst_ip);
                break;
            case ip_protocol_tcp: /* Added in sr_protocol.h by our group */
            case ip_protocol_udp: /* Added in sr_protocol.h by our group */
                printf("TCP/UDP for me.\n");
                sr_create_icmp_t3_template(sr, packet, interface, dst_ip, 3, 3);
                break;
            default:
                printf("Not ICMP/TCP/UDP (type unchecked). Dropping.\n");
        }
    } else {  /* Not for me */
        printf("ICMP/TCP/UDP/... for ");
        printf_addr_ip_int(htonl(ip_hdr->ip_dst));
        printf("\n");
        sr_handle_ip_others(sr, packet, len, interface);
    }
}

void sr_handle_ip_icmp_me(struct sr_instance* sr,
                          uint8_t* packet,
                          unsigned int len,
                          struct sr_if* interface,
                          uint32_t src_ip)
{
    /* Only handle the ICMP echo request (type == 8, code == 0). */
    int icmp_offset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + icmp_offset);
    if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
        printf("Echo Request.\n");

        uint8_t* re_packet = sr_malloc_packet(len, "ICMP echo reply");
        if (!re_packet) return;
        int ip_len = len - sizeof(sr_ethernet_hdr_t);
        sr_init_ethernet_hdr(re_packet, packet, interface);
        sr_init_ip_hdr(re_packet, packet, ip_len, ip_protocol_icmp, src_ip);
        sr_init_icmp_hdr(re_packet, packet, 0, len - icmp_offset);

        sr_arpcache_queue_or_send(sr, re_packet, len, interface);
        free(re_packet);
    } else {
        printf("Not Echo Request (type unchecked).\n");
        printf("       I can only handle ICMP echo request. Dropping.\n");
    }
}

void sr_handle_ip_others(struct sr_instance* sr,
                         uint8_t* packet,
                         unsigned int len,
                         struct sr_if* interface)
{
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* TTL == 0. Life end. */
    if (--ip_hdr->ip_ttl == 0) {
        printf("       TTL == 0. You are a dead man.\n");
        sr_create_icmp_t3_template(sr, packet, interface, interface->ip, 11, 0);
        return;
    }

    /* Life not end, but destination not in routing table. */
    struct sr_if* dest_interface = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
    if (!dest_interface) {
        printf("       Cannot find destination on routing table.\n");
        sr_create_icmp_t3_template(sr, packet, interface, interface->ip, 3, 0);
        return;
    }

    /* Destination found. Re-calculate checksum. */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Look up in ARP cache, if found, send it; if not, queue it. */
    sr_arpcache_queue_or_send(sr, packet, len, dest_interface);
}
