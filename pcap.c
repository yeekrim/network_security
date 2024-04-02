#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "myheader.h"

void Info_Packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    printf("Ethernet Header : src mac - %hhn / dst mac - %hhn", eth->ether_dhost,eth->ether_dhost);

    if (ntohs(eth->ether_type)==0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        printf("IP Header : src ip - %d / dst ip - %d", ip->iph_sourceip,ip->iph_destip);

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)((unsigned char *)ip + (ip->iph_ihl)*4);
            printf("TCP Header : src port - %u / dst port - %u", tcp->tcp_sport,tcp->tcp_dport);
        }
    
    printf("====================================")
    }
    //printf("Message (Up to 100) : \n");
    //printf("%.100s\n", pseudo_tcp.payload);
} 

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 


    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);              
    if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, Info_Packet, NULL);                    

    pcap_close(handle);   //Close the handle
    return 0;
}