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

/* prototype of the packet handler */
void callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main (int argc, char* argv[]) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for (d=alldevs; d; d=d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description != NULL)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i==0) {
        printf("\nNo interfaces found!\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Jump to the selected adapter */
    for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    /* Open the device */
    if ( (pcd= pcap_open_live(d->name,          // name of the device
                              BUFSIZ,            // portion of the packet to capture
                              1,    // promiscuous mode
                              1000,             // read timeout
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nselected device %s is available\n", d->description);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* start the capture */
    pcap_loop(pcd, -1, callback, NULL;
    
    return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    printf ("CALLBACK ");
    struct ether_header *ep;
    unsigned short proto_type;

    // 이더넷 헤더를 가져온다.
    ep = (struct ether_header *)pkt_data;

    // IP 헤더를 가져오기 위해서 이더넷 헤더 크기만큼 offset 한다.
    pkt_data += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다.
    proto_type = ntohs(ep->ether_type);

    // IPv4
    if (proto_type == ETHERTYPE_IP) {
        printf ("IPv4 ");
        struct ip *ip_hdr = (struct ip *)pkt_data;
        
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            printf ("THISIS TCP");
            struct tcphdr *tcp_hdr = (struct tcp *)(pkt_data + ip_hdr->ip_hl * 4);
            printf (" TCP [%s->%s](%s:%d -> %s:%d)\n", 
                inet_ntoa(ip_hdr->ip_src),
                ntohs(tcp_hdr->th_sport),  
                inet_ntoa(ip_hdr->ip_dst), 
                ntohs(tcp_hdr->th_dport)
            );
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            printf ("THISIS UDP");
            struct udphdr *udp_hdr = (struct udp *)(pkt_data + ip_hdr->ip_hl * 4);
            printf (" UDP (%s:%d -> %s:%d)\n", 
                inet_ntoa(ip_hdr->ip_src),
                ntohs(udp_hdr->uh_sport),  
                inet_ntoa(ip_hdr->ip_dst), 
                ntohs(udp_hdr->uh_dport)
            );
        }
        else if (ip_hdr->ip_p == IPPROTO_ICMP) {
            printf ("THISIS ICMP");
            struct icmp *icmp_hdr = (struct icmp *)(pkt_data + ip_hdr->ip_hl * 4);
            printf (" ICMP\n");
            /*
            printf (" ICMP (%s:%d -> %s:%d)\n", 
                inet_ntoa(ip_hdr->ip_src),  
                inet_ntoa(ip_hdr->ip_dst)
            );*/
            /*
            printf (" ICMP (%s:%d -> %s:%d)[type:%c][code:%c]\n", 
                inet_ntoa(ip_hdr->ip_src),  
                inet_ntoa(ip_hdr->ip_dst), 
                icmp_hdr->icmp_type, 
                icmp_hdr->icmp_code
            );*/
        }
    }
    else if (proto_type == ETHERTYPE_IPV6) { 
        printf (" IPv6\n");
    }
    /*
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    
    // unused variables
    (void)(param);
    (void)(pkt_data);

    // convert the timestamp to readable format
    local_tv_sec = header->ts.tv_sec;
    localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
    
    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    */   
}