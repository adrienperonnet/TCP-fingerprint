#include <stdio.h> /* printf */
#include <stdlib.h>   /* exit, EXIT_FAILURE */
#include <string.h> /* stlren */
#include <unistd.h> /* Optarg */
#include <signal.h> /* Ctrl C */
#include <pcap.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h> /*ip structure */
#include <netinet/tcp.h> /* tcp structure */
#include <arpa/inet.h> /* inet_ntoa */
#include "fingerprinter.h" /* New structure to fingerprint a packet  */
#include "fingerprint.h"

/* for the sake of clarity we'll use globals for a few things */
char *device;       /* device to sniff on */
int verbose = 0;    /* verbose output about device */
pcap_t *handle;     /* handle for the opened pcap session */
FILE* etherfile;

/* gracefully handle a Control C */
void ctrl_c ( )
{
    printf ("Exiting\n");
    pcap_breakloop (handle);  /* tell pcap_loop or pcap_dispatch to stop capturing */
    pcap_close(handle);
    fclose(etherfile);
    exit (0);
}

/* usage */
void usage (char *name)
{
    printf ("%s - simple ARP sniffer\n", name);
    printf ("Usage: %s [-i interface] [-l] [-v]\n", name);
    printf ("    -i    interface to sniff on\n");
    printf ("    -l    list available interfaces\n");
    printf ("    -v    print verbose info\n\n");
    exit (1);
}

/* A function to display the content of an arp packet */
char *display_address (u_int8_t add[3])
{
    const int size=sizeof(u_int8_t)*4+sizeof(char)*10;
    char* tmp;
    tmp=malloc(size);
    snprintf(tmp,size,"%d.%d.%d.%d",add[0],add[1],add[2],add[3]);
    return tmp;
}


/* callback function to process a packet when captured */
void process_packet (u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    int length=0; /* Where are we in the packet ? */
    struct ether_header* eth_header = (struct ether_header *) packet;
    struct pkt_fingerprint* fingerprint = malloc(sizeof(struct pkt_fingerprint));
    initialize_fingerprint(fingerprint);
    eth_print(packet,&length);

    if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP){  /* if it is an ARP packet */
        arp_print(packet,&length);
    }
    else if(ntohs (eth_header->ether_type) == ETHERTYPE_IP){
        struct ip* mip = (struct ip*)(packet + length);
        ip_print(packet,&length,fingerprint);
        if (mip->ip_p == 6){/*TCP*/
            struct tcphdr *mytcp=(struct tcphdr*)(packet+length);
            tcp_print(packet,&length,fingerprint);
            if (ntohs(mip->ip_len)-mip->ip_hl*4-mytcp->doff*4 > 0)
              data_print(packet,&length);
            char* fgp=print_fingerprint(fingerprint);
            if(fgp!=NULL){
                /*printf("%s\n",fgp);*/
                printf(".");
                get_ether_fingerprint(fgp);
            }
        }
    }
}


int main (int argc, char *argv[])
{
    char o;     /* for option processing */
    char errbuf[PCAP_ERRBUF_SIZE];  /* pcap error messages buffer */
    bpf_u_int32 netp;   /* ip address of interface */
    bpf_u_int32 maskp;    /* subnet mask of interface */
    /*char *filter = "arp or icmp or tcp port 80"; */  /* filter for BPF (human readable) */
    char *filter = "tcp";   /* filter for BPF (human readable) */
    struct bpf_program fp;  /* compiled BPF filter */
    int r;      /* generic return value */
    pcap_if_t *alldevsp;    /* list of interfaces */
    etherfile = fopen("finger", "r"); 
    if (etherfile==NULL)
        exit(0);

    while ((o = getopt (argc, argv, "i:vl")) > 0)
    {
        switch (o)
        {
            case 'i':
                device = optarg;
                break;
            case 'l':
                if (pcap_findalldevs (&alldevsp, errbuf) < 0)
                {
                    fprintf (stderr, "%s", errbuf);
                    exit (1);
                }
                while (alldevsp != NULL)
                {
                    printf ("%s\n", alldevsp->name);
                    alldevsp = alldevsp->next;
                }
                exit (0);
            case 'v':
                verbose = 1;
                break;
            default:
                usage (argv[0]);
                break;
        }
    }

    /* setup signal handler so Control-C will gracefully exit */
    signal (SIGINT, ctrl_c);

    /* find device for sniffing if needed */
    if (device == NULL)   /* if user hasn't specified a device */
    {
        device = pcap_lookupdev (errbuf); /* let pcap find a compatible device */
        if (device == NULL) /* there was an error */
        {
            fprintf (stderr, "%s", errbuf);
            exit (1);
        }
    }

    /* set errbuf to 0 length string to check for warnings */
    errbuf[0] = 0;

    /* open device for sniffing */
    handle = pcap_open_live (device,  /* device to sniff on */
            BUFSIZ,  /* maximum number of bytes to capture per packet */
            /* BUFSIZE is defined in pcap.h */
            1, /* promisc - 1 to set card in promiscuous mode, 0 to not */
            0, /* to_ms - amount of time to perform packet capture in milliseconds */
            /* 0 = sniff until error */
            errbuf); /* error message buffer if something goes wrong */

    if (handle == NULL)   /* there was an error */
    {
        fprintf (stderr, "%s", errbuf);
        exit (1);
    }

    if (strlen (errbuf) > 0)
    {
        fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
        errbuf[0] = 0;    /* re-set error buffer */
    }

    if (verbose)
    {
        printf ("Using device: %s\n", device);
        /* printf ("Using libpcap version %s", pcap_lib_version); */
    }
    /* find out the datalink type of the connection */
    if (pcap_datalink (handle) != DLT_EN10MB)
    {
        fprintf (stderr, "This program only supports Ethernet cards!\n");
        exit (1);
    }

    /* get the IP subnet mask of the device, so we set a filter on it */
    if (pcap_lookupnet (device, &netp, &maskp, errbuf) == -1)
    {
        fprintf (stderr, "%s", errbuf);
        exit (1);
    }

    /* compile the filter, so we can capture only stuff we are interested in */
    if (pcap_compile (handle, &fp, filter, 0, maskp) == -1)
    {
        fprintf (stderr, "%s", pcap_geterr (handle));
        exit (1);
    }

    /* set the filter for the device we have opened */
    if (pcap_setfilter (handle, &fp) == -1)
    {
        fprintf (stderr, "%s", pcap_geterr (handle));
        exit (1);
    }

    /* we'll be nice and free the memory used for the compiled filter */
    pcap_freecode (&fp);


    if ((r = pcap_loop (handle, -1, process_packet,NULL)) < 0)
    {
        if (r == -1)    /* pcap error */
        {
            fprintf (stderr, "%s", pcap_geterr (handle));
            exit (1);
        }
        /* otherwise return should be -2, meaning pcap_breakloop has been called */
    }
    /* close our devices */
    pcap_close (handle);

    return(0);
}

void tcp_print(register const u_char *packet,int* length, struct pkt_fingerprint* fingerprint)
{
    struct tcphdr *mytcp=(struct tcphdr*)(packet+*length);
    /*    printf("%d\t %d\t %d \t %d",ntohs(mytcp->source),ntohs(mytcp->dest),ntohs(mytcp->ack),ntohs(mytcp->syn));*/

    /* 1 octet = 1 Byte = 8 bits, 5windows= 5*32bits=5*4 Octets */
    /*  printf("\n windows_size=%x\t tcp_option=%x\t TTL= %x\t apr=%d%d%d",mytcp->window,opt,mip->ip_ttl,mytcp->ack,mytcp->psh,mytcp->rst);
        printf("sizeof tcp = %d, iphe=%d\n",sizeof(struct tcphdr),hlen); 
        int begin=sizeof(mytcp);*/
    int hlen=*length+(((mytcp)->doff))*4;
    /* if (hlen<20)
       printf("Malformed TCP");*/

    fingerprint->ack=mytcp->ack;
    fingerprint->syn=mytcp->syn;


    fingerprint->tcp_win_size=(u_int16_t)ntohs(mytcp->window);
    int tmp = *length+sizeof(struct tcphdr);


    u_int8_t* l;
    u_int16_t* mss;
    while (hlen > tmp){
        u_int8_t* tcpopt = (u_int8_t *)(packet+tmp);
        /* printf("[Kind=%x. %d>=%d-]",*tcpopt,hlen,tmp); /* KIND */
        switch (*tcpopt){
            case 0:
                tmp=hlen;
                break;

            case 1:
                fingerprint->nop=1;
                tmp+=1;
                break;

            case 2: 
                mss = (u_int16_t *)(packet+tmp+2);
                fingerprint->mss=ntohs(*mss);
            case 3:
                fingerprint->ws=(u_int8_t) *(packet+tmp+2);
            case 4:
                fingerprint->sack=1;
            case 8:
                fingerprint->timestamp=1;

            default: 
                l = (u_int8_t *)(packet+tmp+1);
                tmp+=(int)*l;
                break;

        }
    }
    *length+=mytcp->doff*4;
    /* There is an option to parse 
       printf("sizeof tcp = %d, iphe=%d",sizeof(struct tcphdr),hlen); */
}

void ip_print(register const u_char *packet,int* length,struct pkt_fingerprint* fingerprint)
{
    struct ip* mip = (struct ip*)(packet + *length);

    *length+=mip->ip_hl*4;
    fingerprint->ttl=mip->ip_ttl;
    fingerprint->defrag=(mip->ip_off&0x4000)>>15;
    fingerprint->length=*length;
    /*printf("\n %d \n",(struct ether_header *) mip-eth_header);*/
    /*  printf("%s\t",(char*) inet_ntoa(mip->ip_src));
        printf("%s\t",(char*)inet_ntoa(mip->ip_dst));
        if (ntohs(mip->ip_len)<=mip->ip_hl*4 || mip->ip_hl<5)
        printf("MALFORMED  IP");*/
}

void arp_print(register const u_char *packet,int* length)
{
    struct ether_arp* arp_packet = (struct ether_arp *) (packet + *length);
    /* printf("%s\t",display_address(arp_packet->arp_spa));
       printf("%s\t",display_address(arp_packet->arp_tpa));*/
}

void data_print(register const u_char *packet,int* length)
{
    u_char* datas = (u_char *)(packet+*length);
    /* printf("%s",datas);*/
}

void eth_print(register const u_char *packet,int* length)
{
    struct ether_header* eth_header = (struct ether_header *) packet+*length;
    /*   printf ("\n %s\t",(char*) ether_ntoa(eth_header->ether_shost));
         printf ("%s\t",(char*) ether_ntoa(eth_header->ether_dhost));*/
    *length+=sizeof(struct ether_header);

}

char* print_fingerprint(const struct pkt_fingerprint* f){
    if (f->syn ==1)
    {
        char* ret=malloc(30);
        char *a="S";
        if (f->ack==1)
            a="A";

        snprintf(ret,30,"%.4x:%.4x:%.2x:%.2x:%d:%d:%d:%d:%s:%.2x",
                f->tcp_win_size,
                f->mss,
                f->ttl,
                f->ws,
                f->sack,
                f->nop,
                f->defrag,
                f->timestamp,
                a,
                f->length);
        return ret;
    }
    else
        return NULL;
}

void initialize_fingerprint(struct pkt_fingerprint* f){
    f->ws=0;
    f->sack=0;
    f->nop=0;
    f->defrag=0;
    f->timestamp=0;
    f->syn=0;
    f->ack=0;
}

void get_ether_fingerprint(const char* f){
    char ligne[200];
    char fgp[29];
    while (fgets(ligne,200,etherfile)){
        strncpy(fgp,ligne,28);
        fgp[28]='\0';
        if (strcmp(fgp,f) == 0){
            printf("\tMATCH : %s",ligne);}
    }
    rewind(etherfile);
}
