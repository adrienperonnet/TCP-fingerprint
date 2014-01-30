void tcp_print(register const u_char *packet,int* length, struct pkt_fingerprint* fingerprint);
void ip_print(register const u_char *packet,int* length,struct pkt_fingerprint* fingerprint);
void arp_print(register const u_char *packet,int* length);
void data_print(register const u_char *packet,int* length);
void eth_print(register const u_char *packet,int* length);
char* print_fingerprint(const struct pkt_fingerprint* f);
void initialize_fingerprint(struct pkt_fingerprint* f);
void get_ether_fingerprint(const char* f);


