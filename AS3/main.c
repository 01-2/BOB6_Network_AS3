#include <pcap.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/if.h>

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN     4
#define ARP_FRAME_TYPE  0x0806
#define ETHER_HW_TYPE   1
#define IP_PROTO_TYPE   0x0800
#define OP_ARP_REQUEST  2

struct arp_header {
    uint16_t        ar_hrd; /* format of hardware address */
    uint16_t        ar_pro; /* format of protocol address */
    uint8_t         ar_hln; /* length of hardware address (ETH_ADDR_LEN) */
    uint8_t         ar_pln; /* length of protocol address (IP_ADDR_LEN) */
    uint16_t        ar_op;
    uint8_t         ar_sha[6];   /* sender hardware address */
    uint32_t         ar_spa;    /* sender protocol address */
    uint8_t         ar_tha[6];   /* target hardware address */
    uint32_t         ar_tpa;    /* target protocol address */
}__attribute__((packed));

int main(int argc, char *argv[]){

        int i = 0;
        int length = 0;
        int offset = 0;
        int sock;
        char errbuf[PCAP_ERRBUF_SIZE];

        struct ifreq ifr;
        struct ether_header eh;
        struct arp_header ah;
        struct in_addr srcip;
        struct in_addr targetip;
        struct sockaddr_in *aptr;

        char address[32] = { 0, };
        u_char tmp[42];
        pcap_t *fp;
        u_char *mymac;

        if(argc != 4){
            printf("Usage : AS3 <interface> <sender ip> <target ip>\n");
            exit(1);
        }

        if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0){
            perror("socket ");
            return 1;
        }

        strcpy(ifr.ifr_name, argv[1]);
        if(ioctl(sock, SIOCGIFHWADDR, &ifr)<0){
            perror("ioctl ");
            return 1;
        }


        if((fp = pcap_open_live(argv[1], 65536, 1, 0, errbuf)) == NULL){
                printf("[!] Packet descriptor Error!!!\n");
                perror(errbuf);
                printf("[!] EXIT process\n");
                exit(0);
        }

        mymac = ifr.ifr_hwaddr.sa_data;
        printf("My MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
               mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);

        /*
         * Gateway MAC
         * Target MAC
         */

        // send arp req
        // make ethernet header
        for(i = 0; i < 6; i++){
            eh.ether_dhost[i] = 0xff;
            eh.ether_shost[i] = mymac[i];
        }
        eh.ether_type = htons(0x0806);

        // make arp header
        ah.ar_hrd = htons(0x0001);
        ah.ar_pro = htons(0x0800);
        ah.ar_hln = 6;
        ah.ar_pln = 4;
        ah.ar_op = htons(0x0001);

        sock=socket(AF_INET, SOCK_DGRAM, 0);
        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
            fprintf(stderr, "ioctl(2) failed\n");
            return 1;
         }

        aptr = (struct sockaddr_in *)&ifr.ifr_addr;
        inet_ntop(AF_INET, &aptr->sin_addr, address, 32);
        printf("%s - %s\n", argv[1], address);


        ah.ar_spa = aptr->sin_addr.s_addr;

        inet_aton(argv[2], &targetip.s_addr);
        ah.ar_tpa = targetip.s_addr; // sender

        for(i = 0; i < 6; i++){
            ah.ar_tha[i] = 0x00;
            ah.ar_sha[i] = mymac[i];
        }

        length = sizeof(struct ether_header);
        offset += length;
        memcpy(tmp, &eh, length);
        length = sizeof(struct arp_header);
        memcpy(tmp+offset, &ah, length);

        if(pcap_sendpacket(fp,tmp,42)!=0){
            fprintf(stderr, "sendpacket_error\n");
            return -1;
        }

        // get reply source MAC

        // send arp reply packet to sender continuously

        return 0;
}
