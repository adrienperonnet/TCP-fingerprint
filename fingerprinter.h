struct pkt_fingerprint{
    u_int16_t tcp_win_size;
    u_int16_t mss;
    u_int8_t ttl;
    u_int8_t ws;
    u_int16_t sack:1;
    u_int16_t nop:1;
    u_int16_t defrag:1;
    u_int16_t timestamp:1;
    u_int16_t syn:1;
    u_int16_t ack:1;
    u_int8_t length;
};



