#include <pcap.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/if.h>


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

    eth.ether_dhost[0] = 0xff;
    eth.ether_dhost[1] = 0xff;
    eth.ether_dhost[2] = 0xff;
    eth.ether_dhost[3] = 0xff;
    eth.ether_dhost[4] = 0xff;
    eth.ether_dhost[5] = 0xff;

}

int main(int argc, char **argv){

        int sock;
        struct ifreq ifr;
        unsigned char *mac = NULL;

        memset(&ifr, 0x00, sizeof(ifr));
        strcpy(ifr.ifr_name, argv[1]);

        if(argc != 4){
            printf("Usage : AS3 <interface> <sender ip> <target ip>\n");
            exit(1);
        }

        int fd=socket(AF_UNIX, SOCK_DGRAM, 0);
        if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0){
            perror("socket ");
            return 1;
        }

        if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
            perror("ioctl ");
            return 1;
        }

        mac = ifr.ifr_hwaddr.sa_data;
        printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", ifr.ifr_name, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    return 0;
}
