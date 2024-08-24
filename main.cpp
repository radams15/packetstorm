#include <algorithm>
#include <map>
#include <cstdio>
#include <memory>

#include <pcap.h>
#include <vector>
#include <netinet/if_ether.h>

#include "protos.h"

#define INPUT_FILE "packet-storm.pcap"
#define ETHERNET_HEADER_LENGTH 14

typedef struct PacketsInfo {
    uint64_t total_data;
    uint64_t num_packets;
    std::map<uint32_t, uint32_t> proto_counts;
    std::map<uint32_t, uint32_t> destinations;
} PacketsInfo_t;

void packet_handler(
    u_char *arg,
    const pcap_pkthdr *header,
    const u_char *packet
    ) {
    // arg is the reference to `packets_info`
    PacketsInfo_t* packets_info = (PacketsInfo_t*)arg;

    ether_header *eth_header;
    eth_header = (ether_header *) packet;

    // Skip non-ip packets
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Ethernet header contains whole packet length
    packets_info->total_data += header->len;
    packets_info->num_packets++;

    // IP header comes immediately after the ethernet header, create pointer to this
    const u_char *ip_header = packet + ETHERNET_HEADER_LENGTH;
    auto* ip = (sniff_ip*) ip_header;

    u_char protocol = ip->ip_p;
    // IP destination address as binary value
    uint32_t ip_dst = ip->ip_dst.s_addr;

    // Increment the count for both the IP address and the protocol
    packets_info->destinations[ip_dst]++;
    packets_info->proto_counts[protocol]++;
}

bool sort_ascending(
    std::pair<uint32_t, uint32_t>& a,
    std::pair<uint32_t, uint32_t>& b
    ) {
    // Simple comparitor to compare the IP request count
    return a.second < b.second;
}


int main(int argc, char** argv) {
    char error_buffer[PCAP_ERRBUF_SIZE];

    PacketsInfo packets_info;

    pcap_t *handle = pcap_open_offline(INPUT_FILE, error_buffer);
    pcap_loop(handle, 0, packet_handler, (u_char*) &packets_info);
    pcap_close(handle);

    // Convert the map to a vector to allow sorting and iterating
    std::vector<std::pair<uint32_t, uint32_t> > vec(packets_info.destinations.begin(), packets_info.destinations.end());
    std::sort(vec.begin(), vec.end(), sort_ascending);
    for(auto it = vec.begin() ; it != vec.end() ; ++it) {
        // Print the ip address and the count
        printf("%s => %d\n", inet_ntoa((in_addr){it->first}), it->second);
    }

    printf(
        R"(
Total packets: %lu
Total Data: %lu B
Average packet size: %.2f B
)",
        packets_info.num_packets,
        packets_info.total_data,
        double(packets_info.total_data) / double(packets_info.num_packets) // mean packet size
    );

    for(int i=0 ; i<NUM_PROTOS ; i++) {
        uint64_t count = packets_info.proto_counts[i];
        if(count > 0) {
            std::string proto_name = protoMap[i];
            printf("%s => %lu packets\n", proto_name.c_str(), count);
        }
    }

    return 0;
}
