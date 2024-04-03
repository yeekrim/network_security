#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "myheader.h"

void Info_Packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    printf("Ethernet Header : src mac - %02x:%02x:%02x:%02x:%02x:%02x / dst mac - %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5], eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type)==0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        printf("IP Header : src ip - %s / dst ip - %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)((unsigned char *)ip + (ip->iph_ihl * 0x0F)*4);
            printf("TCP Header : src port - %u / dst port - %u\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

            int iph_len = (ip->iph_ihl & 0xF) * 4;
            int tcph_len = TH_OFF(tcp) * 4;
            if (ip - iph_len - tcph_len > 0) {
                const unsigned char *message = packet + sizeof(struct ethheader) + iph_len + tcph_len;
                printf("Message : ");
                for (int i=0; i<100; i++) {
                    printf("%c", message[i]);
                }
            }
            printf("\n==================================\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {              
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    // Step 3: Set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    // Step 4: Capture packets
    pcap_loop(handle, -1, Info_Packet, NULL);                    

    pcap_close(handle);   // Close the handle
    return 0;
}