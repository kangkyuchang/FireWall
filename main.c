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
#include <sys/un.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "rule.h"
#include <gtk/gtk.h>
#include "config.h"

extern Rule rules[];
extern int rule_count;

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip";
bpf_u_int32 net;

GtkListStore *allow_rule_store;
GtkListStore *block_rule_store;
GtkListStore *packet_log_store;

GtkWidget *allow_tree_view;
GtkWidget *block_tree_view;

GtkWidget *src_ip_entry, *port_entry, *protocol_combo, *action_combo;

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
        // printf("TCP Packet: %s:%d -> %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    }
    else if(ip_header->ip_p == IPPROTO_UDP) { 
        protocol = "UDP";
        udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        source_port = ntohs(udp_header->uh_sport);
        dest_port = ntohs(udp_header->uh_dport);
        // printf("UDP Packet: %s:%d -> %s:%d\n", source_ip, source_port, dest_ip, dest_port);
    }
    else {
        return;
    }

    Rule *rule = get_rule(source_ip, dest_ip, source_port, dest_port, protocol);
    char action[8];

    if(rule != NULL) {
        strcpy(action, RuleActionName[rule->action]);
    }
    else {
        strcpy(action, "ALLOW");
    }

    time_t timer = time(NULL);
    struct tm* tm_info = localtime(&timer);
    char time_str[10];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    GtkTreeIter iter;
    gtk_list_store_append(packet_log_store, &iter);

    gtk_list_store_set(packet_log_store, &iter, 
                       0, time_str,      
                       1, source_ip,     
                       2, dest_ip,       
                       3, protocol,    
                       4, action,
                       -1); 
}

gboolean pcap_source_callback(GIOChannel *source, GIOCondition condition, gpointer data) {
    pcap_t *handle = (pcap_t *) data;
    pcap_dispatch(handle, 1, packet_handler, NULL);

    return TRUE;
}

void setup_pcap_in_gtk_loop(pcap_t *handle) {
    int fd = pcap_get_selectable_fd(handle);
    if(fd == -1) {
        fprintf(stderr, "pcap FD를 가져올 수 없음. 멀티스레딩이 필요할 수 있습니다.\n");
        return;
    }

    GIOChannel *channel = g_io_channel_unix_new(fd);

    g_io_add_watch(channel, G_IO_IN, (GIOFunc) pcap_source_callback, handle);

    g_io_channel_unref(channel);
}

void create_and_pack_column(GtkTreeView *treeview, const char *title, int column_id) {
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    
    GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(
        title, 
        renderer, 
        "text",    
        column_id,  
        NULL
    );
    gtk_tree_view_append_column(treeview, column);
}

GtkWidget *create_packet_monitoring_page() {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    // GtkListStore 생성 (패킷 로그용)
    packet_log_store = gtk_list_store_new(5, 
                                            G_TYPE_STRING,    // TimeStamp
                                            G_TYPE_STRING,    // Source IP
                                            G_TYPE_STRING,    // Dest IP
                                            G_TYPE_STRING,    // Protocol
                                            G_TYPE_STRING);   // Action/Rule Result

    GtkWidget *tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(packet_log_store));
    
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "시간", 0);
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "출발지 IP", 1);
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "목적지 IP", 2);
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "프로토콜", 3);
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "규칙 결과", 4);

    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled_window), tree_view);
    
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0); 

    return vbox;
}

void on_rule_move(GtkWidget *button, gpointer user_data) {
    const char *button_label = gtk_button_get_label(GTK_BUTTON(button));
    
    GtkListStore *source_store;
    GtkListStore *target_store;
    GtkWidget *tree_view;
    RuleAction new_action;

    if (strcmp(button_label, "-> 차단") == 0) {
        source_store = allow_rule_store;
        target_store = block_rule_store;
        tree_view = allow_tree_view;
        new_action = ACTION_BLOCK;
    } else {

        source_store = block_rule_store;
        target_store = allow_rule_store;
        tree_view = block_tree_view;
        new_action = ACTION_ALLOW;
    }
    
    // GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(gtk_widget_get_parent(gtk_widget_get_parent(gtk_widget_get_parent(button)))));
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
    GtkTreeModel *model;
    GtkTreeIter iter;
    
    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        char *src_ip, *protocol;
        int src_port;
        gtk_tree_model_get(model, &iter, 0, &src_ip, 1, &src_port, 2, &protocol, -1);

        change_rule(src_ip, MY_IP_ADDRESS, src_port, 0, protocol, new_action);
        
        GtkTreeIter new_iter;
        gtk_list_store_append(target_store, &new_iter);
        gtk_list_store_set(target_store, &new_iter, 
                           0, src_ip, 1, src_port, 2, protocol, -1);
                           
        gtk_list_store_remove(source_store, &iter);

        g_free(src_ip); g_free(protocol);
    }
}

void on_add_rule_clicked(GtkWidget *button, gpointer user_data) {
    const char *src_ip = gtk_entry_get_text(GTK_ENTRY(src_ip_entry));
    int port = atoi(gtk_entry_get_text(GTK_ENTRY(port_entry)));
    const char *protocol = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(protocol_combo));
    RuleAction action = string_to_rule_action(gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(action_combo)));

    RuleAction result = add_rule(src_ip, MY_IP_ADDRESS, port, 0, protocol, action);
    GtkListStore *target_store;
    switch(action) {
        case ACTION_ALLOW:
            target_store = allow_rule_store;
            break;
        case ACTION_BLOCK:
            target_store = block_rule_store;
            break;
        default:
            return;
    }
    GtkTreeIter iter;
    gtk_list_store_append(target_store, &iter);
    gtk_list_store_set(target_store, &iter, 
                        0, src_ip, 1, port, 2, protocol, -1);
        
    gtk_entry_set_text(GTK_ENTRY(src_ip_entry), "");
    gtk_entry_set_text(GTK_ENTRY(port_entry), "");
    gtk_combo_box_set_active(GTK_COMBO_BOX(action_combo), ACTION_ALLOW);
}
 
GtkWidget *create_rule_list(const char *title, GtkListStore *store) {
    GtkWidget *frame = gtk_frame_new(title);
    GtkWidget *tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "IP", 0);
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "Port", 1);
    create_and_pack_column(GTK_TREE_VIEW(tree_view), "프로토콜", 2);
    
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled_window), tree_view);
    gtk_container_add(GTK_CONTAINER(frame), scrolled_window);

    return frame;
}

GtkWidget *create_rule_management_page() {
    // 메인 컨테이너: 규칙 목록(HBox) + 규칙 추가 영역(VBox 하단)
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    
    // 상단 HBox: Allow 목록 | 이동 버튼 | Block 목록
    GtkWidget *top_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(main_vbox), top_hbox, TRUE, TRUE, 0); // main_vbox에 top_hbox 추가

    // --- ALLOW 규칙 목록 ---
    allow_rule_store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);
    GtkWidget *allow_list_frame = create_rule_list("허용 규칙 (ALLOW)", allow_rule_store);
    allow_tree_view = gtk_bin_get_child(GTK_BIN(gtk_bin_get_child(GTK_BIN(allow_list_frame))));
    
    // ALLOW 목록을 top_hbox 왼쪽에 배치, 공간 확장
    gtk_box_pack_start(GTK_BOX(top_hbox), allow_list_frame, TRUE, TRUE, 0); 

    // --- 이동 버튼 VBox (중앙) ---
    GtkWidget *button_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *to_block_button = gtk_button_new_with_label("-> 차단");
    GtkWidget *to_allow_button = gtk_button_new_with_label("<- 허용");
    
    // 버튼들이 중앙에 오도록 빈 공간을 추가하여 수직으로 중앙 정렬 효과
    GtkWidget *spacer_top = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *spacer_bottom = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_box_pack_start(GTK_BOX(button_vbox), spacer_top, TRUE, TRUE, 0); // 상단 여백 (확장)
    gtk_box_pack_start(GTK_BOX(button_vbox), to_block_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(button_vbox), to_allow_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(button_vbox), spacer_bottom, TRUE, TRUE, 0); // 하단 여백 (확장)
    
    // 버튼 VBox를 top_hbox 중앙에 배치, 공간 확장 안 함 (FALSE)
    gtk_box_pack_start(GTK_BOX(top_hbox), button_vbox, FALSE, FALSE, 0); 

    // --- BLOCK 규칙 목록 ---
    block_rule_store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);
    GtkWidget *block_list_frame = create_rule_list("차단 규칙 (BLOCK)", block_rule_store);
    block_tree_view = gtk_bin_get_child(GTK_BIN(gtk_bin_get_child(GTK_BIN(GTK_BIN(block_list_frame)))));
    
    // BLOCK 목록을 top_hbox 오른쪽에 배치, 공간 확장 
    gtk_box_pack_start(GTK_BOX(top_hbox), block_list_frame, TRUE, TRUE, 0);

    // ALLOW와 BLOCK 목록에 규칙 추가
    for(int i = 0; i < rule_count; i++) {
        Rule *rule = &rules[i];
        GtkTreeIter iter;
        RuleAction action = rule->action;
        if(action == ACTION_NONE)
            continue;
        GtkListStore *target_store;
        switch(action) {
            case ACTION_ALLOW:
                target_store = allow_rule_store;
                break;
            case ACTION_BLOCK:
                target_store = block_rule_store;
                break;
            default:
                continue;
        }

        gtk_list_store_append(target_store, &iter);
        gtk_list_store_set(target_store, &iter, 
                    0, rule->source_ip,      
                    1, rule->source_port,     
                    2, rule->protocol,
                    -1); 
    }
       

    // --- 새 규칙 추가 영역 ---
    GtkWidget *add_frame = gtk_frame_new("새 규칙 추가");
    GtkWidget *add_grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(add_frame), add_grid);
    gtk_grid_set_row_spacing(GTK_GRID(add_grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(add_grid), 10);
    
    // 입력 필드 및 콤보 박스 생성
    src_ip_entry = gtk_entry_new();
    // GtkWidget *dest_ip_entry = gtk_entry_new();
    port_entry = gtk_entry_new();
    protocol_combo = gtk_combo_box_text_new();
    action_combo = gtk_combo_box_text_new();
    GtkWidget *add_rule_button = gtk_button_new_with_label("규칙 추가");

    // 콤보 박스 항목 채우기
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(protocol_combo), "TCP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(protocol_combo), "UDP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(action_combo), "ALLOW");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(action_combo), "BLOCK");
    gtk_combo_box_set_active(GTK_COMBO_BOX(action_combo), 0); // 기본값 ALLOW

    // 그리드에 위젯 배치 (GtkGrid는 (열, 행, 너비, 높이) 순서로 배치)
    gtk_grid_attach(GTK_GRID(add_grid), gtk_label_new("출발지 IP:"), 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(add_grid), src_ip_entry, 1, 0, 1, 1);
    
    // gtk_grid_attach(GTK_GRID(add_grid), gtk_label_new("목적지 IP:"), 2, 0, 1, 1);
    // gtk_grid_attach(GTK_GRID(add_grid), dest_ip_entry, 3, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(add_grid), gtk_label_new("포트:"), 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(add_grid), port_entry, 3, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(add_grid), gtk_label_new("프로토콜:"), 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(add_grid), protocol_combo, 1, 1, 1, 1);

    gtk_grid_attach(GTK_GRID(add_grid), gtk_label_new("액션:"), 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(add_grid), action_combo, 3, 1, 1, 1);

    gtk_grid_attach(GTK_GRID(add_grid), add_rule_button, 5, 1, 1, 1);

    gtk_box_pack_start(GTK_BOX(main_vbox), add_frame, FALSE, FALSE, 0); // 하단에 고정
    
    // 이벤트 연결
    g_signal_connect(to_block_button, "clicked", G_CALLBACK(on_rule_move), NULL);
    g_signal_connect(to_allow_button, "clicked", G_CALLBACK(on_rule_move), NULL);
    g_signal_connect(add_rule_button, "clicked", G_CALLBACK(on_add_rule_clicked), NULL);

    return main_vbox;
}

int main(int argc, char *argv[]) {
    handle = pcap_open_live("enp3s0", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "이더넷 장치를 열 수 없음: %s\n", errbuf);
        return 2;
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "컴파일을 적용할 수 없음: %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터를 적용할 수 없음: %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    load_rule();

    gtk_init(&argc, &argv);

    setup_pcap_in_gtk_loop(handle);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "방화벽 관리 시스템");
    gtk_window_set_default_size(GTK_WINDOW(window), 1024, 768);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_container_set_border_width(GTK_CONTAINER(notebook), 10);
    gtk_container_add(GTK_CONTAINER(window), notebook);

    GtkWidget *page1 = create_packet_monitoring_page();
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page1, gtk_label_new("패킷 모니터링"));

    GtkWidget *page2 = create_rule_management_page();
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page2, gtk_label_new("규칙 관리"));

    gtk_widget_show_all(window);
    gtk_main();

    pcap_freecode(&fp);
    pcap_close(handle);

    save_rule();

    return 0;
}

