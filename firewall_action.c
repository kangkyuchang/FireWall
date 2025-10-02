#include "firewall_action.h"
#include <stdlib.h>
#include <stdio.h>

void block_ip(const char *ip, int port, const char *protocol) {
    char buffer[100];
    sprintf(buffer, "sudo iptables -A INPUT -s %s -p %s --dport %d -j DROP", ip, protocol, port); 
    system(buffer);
    // printf("Blocked: %s\n", buffer);
}

void unblock_ip(const char *ip, int port, const char *protocol) {
    char buffer[100];
    sprintf(buffer, "sudo iptables -D INPUT -s %s -p %s --dport %d -j DROP", ip, protocol, port); 
    system(buffer);
    // printf("Unblocked: %s\n", buffer); 
}