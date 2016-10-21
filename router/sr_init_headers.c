#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/*------------------------------------------------------------------------------
 * Allocate space for a packet to reply.
 * Parameters:
 * len - the length that is going to allocate.
 * message - the message that would br printed if the allocation is failed.
 * Return:
 * the pointer to the allocated space if it is successfull; NULL otherwise.
 *----------------------------------------------------------------------------*/
uint8_t* sr_malloc_packet(unsigned int len, char* message)
{
    uint8_t* re_packet;
    if ((re_packet = (uint8_t*) malloc(len)) == NULL) {
        printf("!----! Failed to malloc while sending %s packet. Dropping.\n", message);
        return NULL;
    }
    return re_packet;
}

/*------------------------------------------------------------------------------
 * Initialize the ethernet header of re_packet. Use for REPLY ONLY.
 * The destionation of re_packet is set to be the source of packet.
 * The source of re_packet is set to be the address in the interface.
 * The type is set to be the SAME as the one in packet.
 * Parameters:
 * re_packet - the packet that is going to be sent.
 * packet - the original packet received, complete with ethernet frame.
 * interface - the interface that is going to send the packet.
 *----------------------------------------------------------------------------*/
void sr_init_ethernet_hdr(uint8_t* re_packet,
                          uint8_t* packet,
                          struct sr_if* interface)
{
    sr_ethernet_hdr_t* re_ethernet_hdr = get_ethernet_header(re_packet);
    sr_ethernet_hdr_t* ethernet_hdr = get_ethernet_header(packet);
    memcpy(re_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(re_ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    re_ethernet_hdr->ether_type = ethernet_hdr->ether_type;
}

/*------------------------------------------------------------------------------
 * Initialize the ARP header of re_packet.
 * If packet is NULL, then re_packet is initialized to be a broadcast one.
 * Otherwise, the destionation of re_packet is set to be the source of packet;
 * the source of re_packet is set to be the address in the interface;
 * and the operation code is set to be reply (0x0002).
 * Parameters:
 * re_packet - the packet that is going to be sent.
 * packet - the original packet received, complete with ethernet frame.
 * interface - the interface that is going to send the packet.
 *----------------------------------------------------------------------------*/
void sr_init_arp_hdr(uint8_t* re_packet,
                     uint8_t* packet,
                     struct sr_if* interface)
{
    if (!packet) {
        /* TODO Broadcast. */
    } else {
        sr_arp_hdr_t* re_arp_hdr = get_arp_header(re_packet);
        sr_arp_hdr_t* arp_hdr = get_arp_header(packet);
        memcpy(re_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
        memcpy(re_arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
        memcpy(re_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        re_arp_hdr->ar_sip = arp_hdr->ar_tip;
        re_arp_hdr->ar_tip = arp_hdr->ar_sip;
        re_arp_hdr->ar_op = htons(arp_op_reply); /* 0x0002 */
    }
}

/*------------------------------------------------------------------------------
 * Initialize the IP header of re_packet.
 * The destionation of re_packet is set to be the source of packet;
 * the source of re_packet is set to be the address in the interface.
 * Parameters:
 * re_packet - the packet that is going to be sent.
 * packet - the original packet received, complete with ethernet frame.
 * len - the length of the original packet.
 * ip_protocol - for this simple router, only 1 (ICMP) is possible.
 * src_ip - the IP address of the router's interface through which the packet
 *          is going to be sent.
 *----------------------------------------------------------------------------*/
void sr_init_ip_hdr(uint8_t* re_packet,
                    uint8_t* packet,
                    unsigned int len,
                    unsigned int ip_protocol,
                    uint32_t src_ip)
{
    sr_ip_hdr_t* re_ip_hdr = get_ip_header(re_packet);
    sr_ip_hdr_t* ip_hdr = get_ip_header(packet);
    memcpy(re_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));
    re_ip_hdr->ip_len = htons(len);
    re_ip_hdr->ip_id = 0;               /* Imitating sr_solution */
    re_ip_hdr->ip_off = htons(0x4000);  /* Imitating sr_solution */
    re_ip_hdr->ip_ttl = 100;            /* Imitating sr_solution */
    re_ip_hdr->ip_p = ip_protocol;
    re_ip_hdr->ip_dst = ip_hdr->ip_src;
    re_ip_hdr->ip_src = src_ip;
    re_ip_hdr->ip_sum = 0;
    re_ip_hdr->ip_sum = cksum(re_ip_hdr, sizeof(sr_ip_hdr_t));
}

/*------------------------------------------------------------------------------
 * Initialize the ICMP header of re_packet.
 * Parameters:
 * re_packet - the packet that is going to be sent.
 * packet - the original packet received, complete with ethernet frame.
 * interface - the instance of the interface that received the packet.
 * type - 0 for echo request, 3 for unreachable, 11 for timeout.
 * code_or_len - if type is 0, then it refers to the length of the ICMP packet;
 *               otherwise, it refers to the code.
 *----------------------------------------------------------------------------*/
void sr_init_icmp_hdr(uint8_t *re_packet,
                      uint8_t *packet,
                      unsigned int type,
                      unsigned int code_or_len)
{
    sr_icmp_hdr_t* re_icmp_hdr = get_icmp_header(re_packet);
    if (type == 0) {
        /* Not only copy header, but also the payload. */
        sr_icmp_hdr_t* icmp_hdr = get_icmp_header(packet);
        memcpy(re_icmp_hdr, icmp_hdr, code_or_len);
        re_icmp_hdr->icmp_type = re_icmp_hdr->icmp_code = 0;
        re_icmp_hdr->icmp_sum = 0;
        re_icmp_hdr->icmp_sum = cksum(re_icmp_hdr, code_or_len);
    } else if (type == 3 || type == 11) {
        sr_icmp_t3_hdr_t* re_icmp_t3_hdr = (sr_icmp_t3_hdr_t*)re_icmp_hdr;
        sr_ip_hdr_t* ip_hdr = get_ip_header(packet);

        /* Copy the header of IP packet and first 8 bytes. */
        memcpy(re_icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        re_icmp_t3_hdr->icmp_type = type;
        re_icmp_t3_hdr->icmp_code = code_or_len;
        re_icmp_t3_hdr->unused = re_icmp_t3_hdr->next_mtu = 0;
        re_icmp_t3_hdr->icmp_sum = 0;
        re_icmp_t3_hdr->icmp_sum = cksum(re_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    } else {
        printf("       Cannot create other types of ICMP packets.\n");
    }
}

/*------------------------------------------------------------------------------
 * Create an ICMP type 3/11 packet, initialize the headers, then send it.
 * Parameters:
 * sr - the instance of the simple router.
 * packet - the original packet received, complete with ethernet frame.
 * interface - the interface that RECEIVED the original packet, also the one
 *             that is going to send the response packet (ICMP type 3/11).
 * src_ip - the IP address of the router's interface through which the packet
 *          is going to be sent. It is usually the same as interface->ip, but
 *          can be different for ICMP type 3 code 3.
 * type - 3 for destination unreachable, 11 for timeout.
 * code - 0 for net unreachable, 1 for host, 3 for port.
 *----------------------------------------------------------------------------*/
void sr_create_icmp_t3_template(struct sr_instance* sr,
                                uint8_t * packet,
                                struct sr_if* interface,
                                uint32_t src_ip,
                                unsigned int type,
                                unsigned int code)
{
    int headers_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                      sizeof(sr_icmp_t3_hdr_t);
    uint8_t* re_packet = sr_malloc_packet(headers_len, "ICMP type 3/11");
    if (!re_packet) return;
    int ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    sr_init_ethernet_hdr(re_packet, packet, interface);
    sr_init_ip_hdr(re_packet, packet, ip_len, ip_protocol_icmp, src_ip);
    sr_init_icmp_hdr(re_packet, packet, type, code);

    if (type == 3 && code == 0)
        printf("       Sending ICMP network unreachable... ");
    else if (type == 3 && code == 1)
        printf("       Sending ICMP host unreachable... ");
    else if (type == 3 && code == 3)
        printf("       Sending ICMP port unreachable... ");
    else if (type == 11)
        printf("       Sending ICMP time-to-live exceed... ");
    sr_send_packet(sr, re_packet, headers_len, interface->name);
    printf("Done.\n");
    free(re_packet);
}
