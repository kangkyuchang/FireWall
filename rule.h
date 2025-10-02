#ifndef RULE_H
#define RULE_H
#define MAX_PATCKET_SIZE 65536
#define MAX_RULES 100

typedef enum {
    ACTION_ALLOW = 0,
    ACTION_BLOCK = 1,
    ACTION_NONE = 2
} RuleAction;

extern const char *RuleActionName[];

typedef struct Rule {
    char source_ip[16];
    char dest_ip[16];
    int source_port;
    int dest_port;
    char protocol[8];
    RuleAction action;
} Rule;

RuleAction string_to_rule_action(char *string);

int check_rule_exists(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol);

struct Rule* get_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol);

RuleAction add_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol, RuleAction action);

RuleAction change_rule(const char *source_ip, const char *dest_ip, int source_port, int dest_port, const char *protocol, RuleAction action);

void load_rule();

void save_rule();

#endif