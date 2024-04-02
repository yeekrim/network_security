#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "myheader.h"

void Info_Packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    printf("Ethernet Header : src mac - %s / dst mac - %s\n", eth->ether_shost, eth->ether_dhost);

    if (ntohs(eth->ether_type)==0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        printf("IP Header : src ip - %s / dst ip - %s\n", ip->iph_sourceip, ip->iph_destip);

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)((unsigned char *)ip + (ip->iph_ihl)*4);
            printf("TCP Header : src port - %u / dst port - %u\n", tcp->tcp_sport, tcp->tcp_dport);
        
            printf("====================================");

            struct pseudo_tcp *message = tcp->payload;
            printf("Message : %.100s", message);
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
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 

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