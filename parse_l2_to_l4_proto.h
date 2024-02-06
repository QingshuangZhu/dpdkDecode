#ifndef PARSE_L2_TO_L4_PROTO_H_
#define PARSE_L2_TO_L4_PROTO_H_

#include <stdint.h>

#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IP_VER_IPV4		0x04
#define IP_VER_IPV6		0x06

// five tuple
typedef struct {
    uint8_t ip_ver;
    union {
		struct {
			uint32_t src_addr;
			uint32_t dst_addr;
		} ipv4;
		struct {
			uint8_t	src_addr[16];
			uint8_t	dst_addr[16];
		} ipv6;
    };
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto_type;    // transport layer proto
} five_tuple;

// only parse five tuple
// return payload (only udp and tcp payload)
uint8_t* parse_l2_to_l4_proto_info(struct rte_mbuf *buf, five_tuple *tuple_info, uint8_t *tcp_flags);

#ifdef __cplusplus
}
#endif

#endif /* PARSE_L2_TO_L4_PROTO_H_ */