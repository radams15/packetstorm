#include <stdio.h>

#include <pcap.h>
#include <netinet/if_ether.h>

#include "hash_table.h"
#include "protos.h"

#define INPUT_FILE "packet-storm.pcap"
#define ETHERNET_HEADER_LENGTH 14

struct PacketsInfo {
    uint64_t total_data;
    uint64_t num_packets;
    uint64_t proto_counts[NUM_PROTOS];
    void* destinations;
};

void packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
    ) {

    struct PacketsInfo* packets_info = (struct PacketsInfo*) args;

    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    packets_info->total_data += header->len;
    packets_info->num_packets++;

    const u_char *ip_header = packet + ETHERNET_HEADER_LENGTH;
    struct sniff_ip* ip = (struct sniff_ip*) ip_header;

    u_char protocol = ip->ip_p;
    uint8_t length = ip->ip_len;
    uint8_t version = (ip->ip_vhl) >>4 & 0xF;
    uint32_t ip_dst = ip->ip_dst.s_addr;

    hash_table_inc(packets_info->destinations, ip_dst);

    packets_info->proto_counts[protocol]++;
}

void print_packet_info(uint32_t ip, uint32_t count) {
    printf("%s => %d\n", inet_ntoa((struct in_addr){ip}), count);
}

int main(void) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    struct PacketsInfo packets_info = {
        .num_packets =  0,
        .total_data = 0,
        .proto_counts = {0},
        .destinations = hash_table_init()
    };

    pcap_t *handle = pcap_open_offline(INPUT_FILE, error_buffer);

    pcap_loop(handle, 0, packet_handler, (u_char*) &packets_info);

    pcap_close(handle);

    printf(
        "Total packets: %lu\nTotal Data: %lu B\nAverage packet size: %lu B\n",
        packets_info.num_packets,
        packets_info.total_data,
        packets_info.total_data / packets_info.num_packets
    );

    for(int i=0 ; i<NUM_PROTOS ; i++) {
        uint64_t count = packets_info.proto_counts[i];
        if(count > 0) {
            char* proto_name = proto_name_lookup(i);
            printf("%s => %lu\n", proto_name, count);
        }
    }

    hash_table_iter(packets_info.destinations, print_packet_info);

    hash_table_deinit(packets_info.destinations);

    return 0;
}
