#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "rule.h"

Rule rules[MAX_RULES];
int rule_count = 0;

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip";
bpf_u_int32 net;

int is_packet_allowed(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol) {
    for(int i = 0; i < rule_count; i++) {
        Rule *rule = &rules[i];

        if(strcmp(rule->source_ip, "*") != 0 && strcmp(rule->source_ip, source_ip) != 0)
            continue;
        if(strcmp(rule->dest_ip, "*") != 0 && strcmp(rule->dest_ip, dest_ip) != 0)
            continue;
        
        if(rule->source_port != -1 && rule->source_port != source_port)
            continue;
        if(rule->dest_port != -1 && rule->dest_port != source_port)
            continue;

        if(strcmp(rule->protocol, "*") != 0 && strcmp(rule->protocol, protocol) != 0)
            continue;
        
        return strcmp(rule->action, "ALLOW") == 0 ? 1 : 0;
    }
    return 1;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    int source_port, dest_port;
    const char *protocol;

    eth_header = (struct ether_header *) packet;
    if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    if(ip_header->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        source_port = ntohs(tcp_header->th_sport);
        dest_port = ntohs(tcp_header->th_dport);
        printf("TCP Packet: %s:%d -> %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    }
    else if(ip_header->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        source_port = ntohs(udp_header->uh_sport);
        dest_port = ntohs(udp_header->uh_dport);
        printf("UDP Packet: %s:%d -> %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    }
    else if(ip_header->ip_p == IPPROTO_ICMP) {
        protocol = "ICMP";
        printf("ICMP Packet: %s:%d -> %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    }
    else {
        protocol = "OTHER";
    }

    int action = is_packet_allowed(source_ip, dest_ip, source_port, dest_port, protocol);

    if(action == 0) { //pf로 패킷 차단

    }
}

int add_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol, const char *action) {
    if(rule_count >= MAX_RULES) {
        return -1;
    }

    Rule *rule = &rules[rule_count];
    strncpy(rule->source_ip, source_ip, sizeof(rule->source_ip));
    strncpy(rule->dest_ip, dest_ip, sizeof(rule->dest_ip));
    rule->source_port = source_port;
    rule->dest_port = dest_port;
    strncpy(rule->protocol, protocol, sizeof(rule->protocol));
    strncpy(rule->action, action, sizeof(rule->action));

    rule_count ++;
    printf("규칙 추가 성공");
    return 0;
}



int main() {
    handle = pcap_open_live("en7", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "이더넷 장치를 열 수 없음: %s\n", errbuf);
        return 2;
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "컴파일를 적용할 수 없음: %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터를 적용할 수 없음: %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Starting packet capture. Press Ctrl+C to stop.\n");

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

