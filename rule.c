#include "rule.h"
#include "firewall_action.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Rule rules[MAX_RULES];
int rule_count = 0;

const char *RuleActionName[] = {
    "ALLOW",
    "BLOCK",
    "NONE"
};

int check_rule_exists(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol) {
    for(int i = 0; i < rule_count; i++) {
        Rule *rule = &rules[i];

        if(strcmp(rule->source_ip, "*") != 0 && strcmp(rule->source_ip, source_ip) != 0)
            continue;
        if(strcmp(rule->dest_ip, "*") != 0 && strcmp(rule->dest_ip, dest_ip) != 0)
            continue;
        
        if(rule->source_port != -1 && rule->source_port != source_port)
            continue;
        if(rule->dest_port != -1 && rule->dest_port != dest_port)
            continue;

        if(strcmp(rule->protocol, "*") != 0 && strcmp(rule->protocol, protocol) != 0)
            continue;
        
        return 1;
    }
    return 0;
}

struct Rule* get_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol) {
    for(int i = 0; i < rule_count; i++) {
        Rule *rule = &rules[i];

        if(strcmp(rule->source_ip, "*") != 0 && strcmp(rule->source_ip, source_ip) != 0)
            continue;
        if(strcmp(rule->dest_ip, "*") != 0 && strcmp(rule->dest_ip, dest_ip) != 0)
            continue;
        
        if(rule->source_port != -1 && rule->source_port != source_port)
            continue;
        if(rule->dest_port != -1 && rule->dest_port != dest_port)
            continue;

        if(strcmp(rule->protocol, "*") != 0 && strcmp(rule->protocol, protocol) != 0)
            continue;
        
        return rule;
    }
    return NULL;
}

RuleAction add_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol, RuleAction action) {
    if(rule_count >= MAX_RULES) 
        return ACTION_NONE;

    if(check_rule_exists(source_ip, dest_ip, source_port, dest_port, protocol) == 1)
        return ACTION_NONE;

    Rule *rule = &rules[rule_count++];
    strncpy(rule->source_ip, source_ip, sizeof(rule->source_ip));
    strncpy(rule->dest_ip, dest_ip, sizeof(rule->dest_ip));
    rule->source_port = source_port;
    rule->dest_port = dest_port;
    strncpy(rule->protocol, protocol, sizeof(rule->protocol));
    rule->action = action;

    if(action == ACTION_BLOCK) {
        block_ip(source_ip, source_port, protocol);
    }
    
    return action;
}

RuleAction change_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol, RuleAction action) { 
    Rule *rule = get_rule(source_ip, dest_ip, source_port, dest_port, protocol);
    if(rule == NULL)
        return ACTION_NONE;
    if(rule->action == action)
        return ACTION_NONE;
    if(action == ACTION_ALLOW) {
        unblock_ip(source_ip, source_port, protocol);
    }
    else {
        block_ip(source_ip, source_port, protocol);
    }
    rule->action = action;
    return action;
}

RuleAction string_to_rule_action(char *string) {
    for(int i = 0; i < 3; i++) {
        const char *action = RuleActionName[i];
        if(strcmp(action, string) == 0) {
            return (RuleAction) i;
        }
    }
    return ACTION_NONE;
}

void load_rule() {
    FILE *fp = fopen("./blocked_ip.txt", "r");
    if(fp == NULL) {
        fp = fopen("./blocked_ip.txt", "w");
    }
    else {
        char line[64];
        const char split[] = " \t\n";
        while(fgets(line, sizeof(line), fp)) {
            char *source_ip = strtok(line, split);
            int source_port = atoi(strtok(NULL, split));
            char *dest_ip = strtok(NULL, split);
            int dest_port = atoi(strtok(NULL, split));
            char *protocol = strtok(NULL, split);
            RuleAction action = string_to_rule_action(strtok(NULL, split));
            add_rule(source_ip, dest_ip, source_port, dest_port, protocol, action);
        }
    }
    fclose(fp);
}

void save_rule() {
    FILE *fp = fopen("./blocked_ip.txt", "w");
    const char *src_ip, *dest_ip, *protocol, *action;
    int src_port, dest_port;
    for(int i = 0; i < rule_count; i++) {
        Rule *rule = &rules[i];
        src_ip = rule->source_ip;
        src_port = rule->source_port;
        dest_ip = rule->dest_ip;
        dest_port = rule->dest_port;
        protocol = rule->protocol;
        action = RuleActionName[rule->action];
        fprintf(fp, "%s %d %s %d %s %s\n", src_ip, src_port, dest_ip, dest_port, protocol, action);
        if(rule->action == ACTION_BLOCK) {
            unblock_ip(src_ip, src_port, protocol);
        }
    }
    fclose(fp);
}