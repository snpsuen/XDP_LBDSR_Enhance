struct serveraddr {
  uint32_t ipaddr;
  uint8_t macaddr[6];
};

struct dispatchmsg_t {
   uint64_t timestamp;
   uint32_t saddr;
   uint32_t backendkey;
};

struct five_tuple {
    uint8_t  protocol;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t port_source;
    uint16_t port_destination;
};
