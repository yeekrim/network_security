#include <stdio.h>
#include <pcap.h>
#include "myheader.h"

void Info_Packet() {
    printf("Ethernet Header : src mac - %s / dst mac - %s", ethheader.ether_shost,ethheader.ether_dhost);
    printf("IP Header : src ip - %s / dst ip - %s", ipheader.iph_sourceip,ipheader.iph_destip);
    printf("TCP Header : src ip - %s / dst ip - %s", tcpheader.iph_sourceip,ipheader.iph_destip);
    printf("Message (Up to 100) : \n");
    printf("%.100s\n", pseudo_tcp.payload)
} 

int main() {
    pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 


  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);              
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}