//
// Created by rhys on 23/07/24.
//

#include "protos.h"

#include <stddef.h>
#include <netinet/in.h>


char* proto_names[] = {
    "IP",
    "ICMP",
    "IGMP",
    "IPIP",
    "TCP",
    "EGP",
    "PUP",
    "UDP",
    "IDP",
    "TP",
    "DCCP",
    "RSVP",
    "GRE",
    "ESP",
    "AH",
    "MTP",
    "BEETPH",
    "ENCAP",
    "PIM",
    "COMP",
    "SCTP",
    "UDPLITE",
    "MPLS",
    "ETHERNET",
    "RAW",
    "MPTCP"
};

uint16_t proto_ids[] = {
    IPPROTO_IP,
    IPPROTO_ICMP,
    IPPROTO_IGMP,
    IPPROTO_IPIP,
    IPPROTO_TCP,
    IPPROTO_EGP,
    IPPROTO_PUP,
    IPPROTO_UDP,
    IPPROTO_IDP,
    IPPROTO_TP,
    IPPROTO_DCCP,
    IPPROTO_RSVP,
    IPPROTO_GRE,
    IPPROTO_ESP,
    IPPROTO_AH,
    IPPROTO_MTP,
    IPPROTO_BEETPH,
    IPPROTO_ENCAP,
    IPPROTO_PIM,
    IPPROTO_COMP,
    IPPROTO_SCTP,
    IPPROTO_UDPLITE,
    IPPROTO_MPLS,
    IPPROTO_ETHERNET,
    IPPROTO_RAW,
    IPPROTO_MPTCP
};

char* proto_name_lookup(uint8_t proto_id) {
    for(uint16_t i=0 ; i<sizeof(proto_ids) ; i++) {
        if(proto_ids[i] == proto_id) {
            return proto_names[i];
        }
    }

    return NULL;
}