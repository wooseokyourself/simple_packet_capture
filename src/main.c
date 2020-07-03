#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <pcap.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

static clock_t start;

void _print_IPv4_time_and_mac_addr (struct ether_header *ep) {
    double recv_time = (double)(clock()-start)/CLOCKS_PER_SEC;
    printf ("%f: ", recv_time);
    printf ("[");
    for (int i=0; i<6; i++) {
        printf ("%02X", ep->ether_shost[i]);
        if (i == 5)
            break;
        putchar(':');
    }
    printf ("->");
    for (int i=0; i<6; i++) {
        printf ("%02X", ep->ether_dhost[i]);
        if (i == 5)
            break;
        putchar(':');
    }
    printf ("]");
}

void print_IPv4 (int PROTO_TYPE, struct ip* ip_hdr, void* proto_hdr) {
    if (PROTO_TYPE == IPPROTO_TCP) {
        printf ("%c[1;31m", 27);

        struct tcphdr *tcp_hdr = (struct tcphdr *)proto_hdr;
        _print_IPv4_time_and_mac_addr (ip_hdr);
        printf ("(%15s->%15s) TCP\t[port:%5d->%5d][seq:%10u][ack:%10u]", 
            inet_ntoa(ip_hdr->ip_src),
            inet_ntoa(ip_hdr->ip_dst), 
            ntohs(tcp_hdr->th_sport),  
            ntohs(tcp_hdr->th_dport), 
            tcp_hdr->th_seq, 
            tcp_hdr->th_ack
        );

        printf ("%c[0m\n", 27);
    }
    else if (PROTO_TYPE == IPPROTO_UDP) {
        printf ("%c[1;36m", 27);

        struct udphdr *udp_hdr = (struct udphdr *)proto_hdr;
        _print_IPv4_time_and_mac_addr (ip_hdr);
        printf ("(%15s->%15s) UDP\t[port:%5d->%5d]", 
            inet_ntoa(ip_hdr->ip_src),
            inet_ntoa(ip_hdr->ip_dst),
            ntohs(udp_hdr->uh_sport),  
            ntohs(udp_hdr->uh_dport)
        );

        printf ("%c[0m\n", 27);
    }
    else if (PROTO_TYPE == IPPROTO_ICMP) {
        printf ("%c[1;33m", 27);

        struct icmp *icmp_hdr = (struct icmp *)proto_hdr;
        _print_IPv4_time_and_mac_addr (ip_hdr);
        printf ("(%15s->%15s) ICMP\t[type:%2d][code:%2d]", 
            inet_ntoa(ip_hdr->ip_src),  
            inet_ntoa(ip_hdr->ip_dst), 
            icmp_hdr->icmp_type, 
            icmp_hdr->icmp_code
        );

        printf ("%c[0m\n", 27);
    }
}

/* Callback function invoked by libpcap for every incoming packet */
void callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct ether_header *ep;
    unsigned short proto_type;

    // 이더넷 헤더를 가져온다.
    ep = (struct ether_header *)pkt_data;

    // IP 헤더를 가져오기 위해서 이더넷 헤더 크기만큼 offset 한다.
    pkt_data += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다.
    proto_type = ntohs(ep->ether_type);

    if (proto_type == ETHERTYPE_IP) { // IPv4
        struct ip *ip_hdr = (struct ip *)pkt_data;
        print_IPv4 (ip_hdr->ip_p, ip_hdr, (pkt_data + ip_hdr->ip_hl * 4));
    }
}


int main (int argc, char* argv[]) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf (stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    for (d=alldevs; d; d=d->next) {
        printf ("%d. %s", ++i, d->name);
        if (d->description != NULL)
            printf (" (%s)\n", d->description);
        else
            printf (" (No description available)\n");
    }
    
    if (i==0) {
        printf ("\nNo interfaces found!\n");
        return -1;
    }
    
    printf ("Enter the interface number (1-%d):",i);
    scanf ("%d", &inum);
    
    if (inum < 1 || inum > i) {
        printf ("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs (alldevs);
        return -1;
    }
    
    for (d=alldevs, i=0; i< inum-1; d=d->next, i++); // jump
    
    if ( (pcd= pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nselected device %s is available\n", d->description);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    start = clock();

    /* start the capture */
    pcap_loop(pcd, -1, callback, NULL);
    
    printf ("exit\n");
    return 0;
}
