#include <pcap.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>


typedef struct{
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arphdr;

void getMACaddr(unsigned char *packet, int s){
    struct ether_header eth;
    int curlen = 0;

    eth->ether_dhost[0] = 0xff;
    eth->ether_dhost[1] = 0xff;
    eth->ether_dhost[2] = 0xff;
    eth->ether_dhost[3] = 0xff;
    eth->ether_dhost[4] = 0xff;
    eth->ether_dhost[5] = 0xff;

}

int main(int argc, char **argv){

        char errbuf[PCAP_ERRBUF_SIZE];
        unsigned char packet[1500];

        pcap_if_t *alldevs;
        pcap_if_t *d;
        pcap_t *adhandle;

        // struct pcap_pkthdr *header;
        // const unsigned char *pkt_data;

        if(argc != 4){
            printf("Usage : AS3 <interface> <sender ip> <target ip>");
            exit(1);
        }

        if(pcap_findalldevs(&alldevs, errbuf) == -1){
                fprintf(stderr, "Error in pcap_findalldevs : %s\n", errbuf);
                exit(1);
        }

        for (d = alldevs; d; d = d->next){
            if(strcmp(d->name, argv[1])){
                printf("Target : %s ", argv[1]);
                printf(" (%s)\n", d->description);
                break;
            }
        }

        if((adhandle = pcap_open_live(d->name, 65536, 1, 0, errbuf)) == NULL){
            printf("[!] Packet descriptor Error!!!\n");
            perror(errbuf);
            printf("[!] EXIT process\n");
            pcap_freealldevs(alldevs);
            exit(0);
        }

        printf("\nListening on %s...\n", d->name);

    return 0;
}
