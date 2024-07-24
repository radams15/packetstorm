//
// Created by rhys on 23/07/24.
//

#ifndef PROTOS_H
#define PROTOS_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#define NUM_PROTOS 512

char* proto_name_lookup(uint8_t proto_id);

struct sniff_ip
{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#endif //PROTOS_H
