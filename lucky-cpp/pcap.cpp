#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

void my_callback(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt)
{
        printf("my callback.\n");
        printf("pkthdr.len:%d.\n", pkthdr->len);
        printf("pkthdr.caplen:%d.\n", pkthdr->caplen);
        printf("pkthdr.ts.tv_sec:%ld.\n", pkthdr->ts.tv_sec);
        printf("pkt: %s.\n", pkt);
        return;
}

void ifprint(pcap_if_t *d)
{
        pcap_addr_t *a;
        char ip6str[128];

        /* Name */
        printf("%s\n",d->name);

        /* Description */
        if (d->description)
                printf("\tDescription: %s\n",d->description);

        /* Loopback Address*/
        printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

        /* IP addresses */
        for(a=d->addresses;a;a=a->next) {
                printf("\tAddress Family: #%d\n",a->addr->sa_family);

                switch(a->addr->sa_family)
                {
                        case AF_INET:
                                printf("\tAddress Family Name: AF_INET\n");
                                if (a->addr)
                                        printf("\tAddress: %s\n",inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
                                if (a->netmask)
                                        printf("\tNetmask: %s\n",inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
                                if (a->broadaddr)
                                        printf("\tBroadcast Address: %s\n",inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr));
                                if (a->dstaddr)
                                        printf("\tDestination Address: %s\n",inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr));
                                break;

                        default:
                                printf("\tAddress Family Name: Unknown\n");
                                break;
                }
        }
        printf("\n");
}



int main(int argc, char *argv[])
{
        pcap_t *handle;         /* Session handle */
        char *dev;          /* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
        struct bpf_program fp;      /* The compiled filter */
        char filter_exp[] = "port 8081";  /* The filter expression */
        bpf_u_int32 mask;       /* Our netmask */
        bpf_u_int32 net;        /* Our IP */
        struct pcap_pkthdr header;  /* The header that pcap gives us */
        const u_char *packet;       /* The actual packet */

        /* List all devices */
        pcap_if_t *alldevs;
        if(pcap_findalldevs(&alldevs, errbuf) == -1)
        {
                fprintf(stderr, "Couldn't find alldevs:%s.\n", errbuf);
                return 2;
        }
        for(pcap_if_t *d = alldevs; d; d=d->next)
        {
                ifprint(d);
        //        printf("dev: %s %s.\n",d->name, inet_ntoa( ((struct sockaddr_in *)(d->addresses->addr))->sin_addr ));
        }

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
        }
        printf("device is %s\n", dev);

        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }
        in_addr _ip, _mask;
        _ip.s_addr = net;
        _mask.s_addr = mask;
        printf("IPaddr: %s.\n", inet_ntoa(_ip));
        printf("Mask: %s.\n", inet_ntoa(_mask));


        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        }


        pcap_loop(handle, 10, my_callback, NULL);


        /* And close the session */
        pcap_close(handle);
        return(0);
}
