#include <algorithm>
#include <map>
#include <cstdio>

#include <pcap.h>
#include <vector>
#include <netinet/if_ether.h>

#include "protos.h"

#define INPUT_FILE "packet-storm.pcap"
#define ETHERNET_HEADER_LENGTH 14

struct PacketsInfo {
    uint64_t total_data;
    uint64_t num_packets;
    std::map<uint32_t, uint32_t> proto_counts;
    std::map<uint32_t, uint32_t> destinations;
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

    packets_info->destinations[ip_dst]++;
    packets_info->proto_counts[protocol]++;
}

void print_packet_info(uint32_t ip, uint32_t count) {
    printf("%s => %d\n", inet_ntoa((struct in_addr){ip}), count);
}

bool sort_ascending(
    std::pair<uint32_t, uint32_t>& a,
    std::pair<uint32_t, uint32_t>& b
    ) {
    return a.second < b.second;
}


int main(void) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    struct PacketsInfo packets_info = {
        .total_data = 0,
        .num_packets =  0,
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


    std::vector<std::pair<uint32_t, uint32_t> > vec(packets_info.destinations.begin(), packets_info.destinations.end());
    std::sort(vec.begin(), vec.end(), sort_ascending);
    for(auto it = vec.begin() ; it != vec.end() ; it++) {
        print_packet_info(it->first, it->second);
    }

    for(int i=0 ; i<NUM_PROTOS ; i++) {
        uint64_t count = packets_info.proto_counts[i];
        if(count > 0) {
            const char* proto_name = proto_name_lookup(i).c_str();
            printf("%s => %lu\n", proto_name, count);
        }
    }

    return 0;
}
