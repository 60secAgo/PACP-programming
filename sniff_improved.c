/*
 * PCAP Programming Assignment
 * Based on the provided sniff_improved.c and myheader.h examples.
 *
 * Features:
 *  - Capture TCP packets only using PCAP filter "tcp"
 *  - Print Ethernet header: source MAC / destination MAC
 *  - Print IP header: source IP / destination IP
 *  - Print TCP header: source port / destination port
 *  - Print HTTP message when TCP payload looks like HTTP data
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "myheader.h"

#define SNAP_LEN 65535

static void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int is_http_port(int port)
{
    return port == 80 || port == 8080 || port == 8000;
}

static int looks_like_http(const u_char *payload, int payload_len)
{
    if (payload_len < 4) {
        return 0;
    }

    if (strncmp((const char *)payload, "GET ", 4) == 0) return 1;
    if (strncmp((const char *)payload, "POST ", 5) == 0) return 1;
    if (strncmp((const char *)payload, "HEAD ", 5) == 0) return 1;
    if (strncmp((const char *)payload, "PUT ", 4) == 0) return 1;
    if (strncmp((const char *)payload, "DELETE ", 7) == 0) return 1;
    if (strncmp((const char *)payload, "HTTP/", 5) == 0) return 1;

    return 0;
}

static void print_http_message(const u_char *payload, int payload_len)
{
    int print_len = payload_len;

    if (print_len > 1000) {
        print_len = 1000;
    }

    printf("\n[HTTP Message]\n");

    for (int i = 0; i < print_len; i++) {
        unsigned char c = payload[i];

        if (isprint(c) || c == '\n' || c == '\r' || c == '\t') {
            putchar(c);
        } else {
            putchar('.');
        }
    }

    if (payload_len > print_len) {
        printf("\n... truncated ...");
    }

    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    (void)args;

    int ethernet_header_len = sizeof(struct ethheader);

    if (header->caplen < (bpf_u_int32)ethernet_header_len) {
        return;
    }

    struct ethheader *eth = (struct ethheader *)packet;

    /* 0x0800 means IPv4 packet. Ignore ARP, IPv6, etc. */
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    if (header->caplen < (bpf_u_int32)(ethernet_header_len + sizeof(struct ipheader))) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + ethernet_header_len);

    /* IP header length is stored in 4-byte words. */
    int ip_header_len = ip->iph_ihl * 4;

    if (ip_header_len < 20) {
        return;
    }

    if (header->caplen < (bpf_u_int32)(ethernet_header_len + ip_header_len)) {
        return;
    }

    /* This program processes TCP packets only. */
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    const u_char *tcp_start = packet + ethernet_header_len + ip_header_len;

    if (header->caplen < (bpf_u_int32)(ethernet_header_len + ip_header_len + sizeof(struct tcpheader))) {
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)tcp_start;

    /* TCP data offset is stored in 4-byte words. */
    int tcp_header_len = TH_OFF(tcp) * 4;

    if (tcp_header_len < 20) {
        return;
    }

    int total_ip_len = ntohs(ip->iph_len);
    int payload_offset = ethernet_header_len + ip_header_len + tcp_header_len;
    int tcp_payload_len = total_ip_len - ip_header_len - tcp_header_len;

    if (tcp_payload_len < 0) {
        return;
    }

    if (header->caplen < (bpf_u_int32)payload_offset) {
        return;
    }

    int captured_payload_len = header->caplen - payload_offset;
    if (tcp_payload_len > captured_payload_len) {
        tcp_payload_len = captured_payload_len;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &(ip->iph_destip), dst_ip, sizeof(dst_ip));

    int src_port = ntohs(tcp->tcp_sport);
    int dst_port = ntohs(tcp->tcp_dport);

    printf("\n====================================================\n");

    printf("[Ethernet Header]\n");
    printf("Source MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("\n[IP Header]\n");
    printf("Source IP       : %s\n", src_ip);
    printf("Destination IP  : %s\n", dst_ip);
    printf("IP Header Len   : %d bytes\n", ip_header_len);

    printf("\n[TCP Header]\n");
    printf("Source Port     : %d\n", src_port);
    printf("Destination Port: %d\n", dst_port);
    printf("TCP Header Len  : %d bytes\n", tcp_header_len);

    const u_char *payload = packet + payload_offset;

    if (tcp_payload_len > 0 &&
        (is_http_port(src_port) || is_http_port(dst_port) ||
         looks_like_http(payload, tcp_payload_len))) {
        print_http_message(payload, tcp_payload_len);
    }

    printf("====================================================\n");
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    char *dev = NULL;

    if (argc >= 2) {
        dev = argv[1];
    } else {
        fprintf(stderr, "Usage: sudo %s <network_interface>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s enp0s3\n", argv[0]);
        return 1;
    }

    /* Step 1: Open live pcap session on NIC */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    /* This code assumes Ethernet packets. */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "This program supports Ethernet interfaces only.\n");
        fprintf(stderr, "Selected interface datalink type: %s\n",
                pcap_datalink_val_to_name(pcap_datalink(handle)));
        pcap_close(handle);
        return 1;
    }

    /* Step 2: Compile filter_exp into BPF pseudo-code */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error");
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("Listening on %s...\n", dev);
    printf("Filter: %s\n", filter_exp);
    printf("Press Ctrl+C to stop.\n");

    /* Step 3: Capture packets */
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
