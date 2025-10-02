#ifndef FIREWALL_ACTION_H
#define FIREWALL_ACTION_H

void block_ip(const char *ip, int port, const char *protocol);

void unblock_ip(const char *ip, int port, const char *protocol);

#endif