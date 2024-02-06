#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "parse_l2_to_l4_proto.h"

// only parse five tuple
// return payload (only udp and tcp payload)
uint8_t* parse_l2_to_l4_proto_info(struct rte_mbuf *buf, five_tuple *tuple_info, uint8_t *tcp_flags) 
{
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr = NULL;
	struct rte_tcp_hdr *tcp_hdr = NULL;
	struct rte_udp_hdr *udp_hdr = NULL;
	char *payload = NULL;
	if (NULL == buf || NULL == tuple_info) {
		printf("[%s][%s][line %d] rte_mbuf or tuple_info is invalid!\n",__FILE__,__func__,__LINE__);
		return NULL;
	}
	if (buf->packet_type & RTE_PTYPE_L3_IPV4) {
		tuple_info->ip_ver = IP_VER_IPV4;
		ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
		tuple_info->ipv4.src_addr = ipv4_hdr->src_addr;
		tuple_info->ipv4.dst_addr = ipv4_hdr->dst_addr;
		tuple_info->proto_type = ipv4_hdr->next_proto_id;
		tuple_info->src_port = rte_be_to_cpu_16(*(uint16_t *)(ipv4_hdr + 1)),
		tuple_info->dst_port = rte_be_to_cpu_16(*((uint16_t *)(ipv4_hdr + 1) + 1));
		if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
			tcp_hdr = (struct rte_tcp_hdr *)RTE_PTR_ADD(ipv4_hdr, sizeof(struct rte_ipv4_hdr));
			*tcp_flags = tcp_hdr->tcp_flags;
			// payload = (uint8_t *)(tcp_hdr + 1);
			payload = (uint8_t *)tcp_hdr + ((tcp_hdr->data_off & 0xf0) >> 2);
		} else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			udp_hdr = (struct rte_udp_hdr *)RTE_PTR_ADD(ipv4_hdr, sizeof(struct rte_ipv4_hdr));
			payload = (uint8_t *)(udp_hdr + 1);
        }
	} else {
		tuple_info->ip_ver = IP_VER_IPV6;
		ipv6_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
		memcpy(tuple_info->ipv6.src_addr, ipv6_hdr->src_addr, sizeof(tuple_info->ipv6.src_addr));
		memcpy(tuple_info->ipv6.dst_addr, ipv6_hdr->dst_addr, sizeof(tuple_info->ipv6.dst_addr));
		tuple_info->proto_type = ipv6_hdr->proto;
		tuple_info->src_port = rte_be_to_cpu_16(*(uint16_t *)(ipv6_hdr + 1)),
		tuple_info->dst_port = rte_be_to_cpu_16(*((uint16_t *)(ipv6_hdr + 1) + 1));
		if (ipv6_hdr->proto == IPPROTO_TCP) {
			tcp_hdr = (struct rte_tcp_hdr *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct rte_ipv6_hdr));
			*tcp_flags = tcp_hdr->tcp_flags;
			// payload = (uint8_t *)(tcp_hdr + 1);
			payload = (uint8_t *)tcp_hdr + ((tcp_hdr->data_off & 0xf0) >> 2);
		}else if (ipv6_hdr->proto == IPPROTO_UDP) {
			udp_hdr = (struct rte_udp_hdr *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct rte_ipv6_hdr));
			payload = (uint8_t *)(udp_hdr + 1);
		}
	}
	//printf("src_addr: %u, dst_addr: %u, src_port: %u, dst_port: %u, proto_type: %u\n", 
	//	tuple_info->ipv4.src_addr, tuple_info->ipv4.dst_addr, tuple_info->src_port, tuple_info->dst_port, tuple_info->proto_type);
	return payload;
}