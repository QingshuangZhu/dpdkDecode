/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_prefetch.h>
#include <rte_distributor.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_common.h>

#include "parse_l2_to_l4_proto.h"
#include "parse_app_proto.h"
#include "flow_table.h"
#include "output.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS ((64*1024)-1)
#define MBUF_CACHE_SIZE 128
#define BURST_SIZE 64
#define SCHED_RX_RING_SZ 8192
#define SCHED_TX_RING_SZ 65536
#define BURST_SIZE_TX 32
#define MSG_RING_SZ 65536

#define RTE_LOGTYPE_DPDKDECODE RTE_LOGTYPE_USER1

/* mask of enabled ports */
static uint32_t enabled_port_mask;
volatile uint8_t quit_signal_tx;
volatile uint8_t quit_signal_rx;
volatile uint8_t quit_signal_dist;
volatile uint8_t quit_signal_work;
volatile uint8_t quit_signal_flow_tbl_age;
volatile uint8_t quit_signal_output;
unsigned int num_workers;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP |
				RTE_ETH_RSS_TCP | RTE_ETH_RSS_SCTP,
		}
	},
};

struct output_buffer {
	unsigned count;
	struct rte_mbuf *mbufs[BURST_SIZE];
};

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rxRings = 1, txRings = 1;
	int retval;
	uint16_t q;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	port_conf.rx_adv_conf.rss_conf.rss_hf &=
		dev_info.flow_type_rss_offloads;
	if (port_conf.rx_adv_conf.rss_conf.rss_hf !=
			port_conf_default.rx_adv_conf.rss_conf.rss_hf) {
		printf("Port %u modified RSS hash function based on hardware support,"
			"requested:%#"PRIx64" configured:%#"PRIx64"\n",
			port,
			port_conf_default.rx_adv_conf.rss_conf.rss_hf,
			port_conf.rx_adv_conf.rss_conf.rss_hf);
	}

	retval = rte_eth_dev_configure(port, rxRings, txRings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rxRings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
						rte_eth_dev_socket_id(port),
						NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < txRings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
						rte_eth_dev_socket_id(port),
						&txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct rte_eth_link link;

	do {
		retval = rte_eth_link_get_nowait(port, &link);
		if (retval < 0) {
			printf("Failed link get (port %u): %s\n",
				port, rte_strerror(-retval));
			return retval;
		} else if (link.link_status)
			break;

		printf("Waiting for Link up on port %"PRIu16"\n", port);
		sleep(1);
	} while (!link.link_status);

	if (!link.link_status) {
		printf("Link down on port %"PRIu16"\n", port);
		return 0;
	}

	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval < 0) {
		printf("Failed to get MAC address (port %u): %s\n",
				port, rte_strerror(-retval));
		return retval;
	}

	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

struct lcore_params {
	unsigned worker_id;
	struct rte_distributor *d;
	struct rte_ring *rx_dist_ring;
	struct rte_ring *dist_tx_ring;
	struct rte_ring *worker_output_ring;
	struct rte_mempool *mem_pool;
};

static int
lcore_rx(struct lcore_params *p)
{
	const uint16_t nb_ports = rte_eth_dev_count_avail();
	const int socket_id = rte_socket_id();
	uint16_t port;
	struct rte_mbuf *bufs[BURST_SIZE*2];

	RTE_ETH_FOREACH_DEV(port) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0)
			continue;

		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) != socket_id)
			printf("WARNING, port %u is on remote NUMA node to "
					"RX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("\nCore %u doing packet RX.\n", rte_lcore_id());
	port = 0;
	while (!quit_signal_rx) {

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs,
				BURST_SIZE);
		if (unlikely(nb_rx == 0)) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}

		/*
		 * Swap the following two lines if you want the rx traffic
		 * to go directly to tx, no distribution.
		 */
		struct rte_ring *out_ring = p->rx_dist_ring;
		/* struct rte_ring *out_ring = p->dist_tx_ring; */

		uint16_t sent = rte_ring_enqueue_burst(out_ring,
				(void *)bufs, nb_rx, NULL);

		if (unlikely(sent < nb_rx)) {
			RTE_LOG_DP(DEBUG, DPDKDECODE,
				"%s:Packet loss due to full ring\n", __func__);
			while (sent < nb_rx)
				rte_pktmbuf_free(bufs[sent++]);
		}
		if (++port == nb_ports)
			port = 0;
	}
	printf("\nCore %u exiting rx task.\n", rte_lcore_id());
	/* set distributor threads quit flag */
	quit_signal_dist = 1;
	return 0;
}

static inline void
flush_one_port(struct output_buffer *outbuf, uint8_t outp)
{
	unsigned int nb_tx = rte_eth_tx_burst(outp, 0,
			outbuf->mbufs, outbuf->count);

	if (unlikely(nb_tx < outbuf->count)) {
		do {
			rte_pktmbuf_free(outbuf->mbufs[nb_tx]);
		} while (++nb_tx < outbuf->count);
	}
	outbuf->count = 0;
}

static inline void
flush_all_ports(struct output_buffer *tx_buffers)
{
	uint16_t outp;

	RTE_ETH_FOREACH_DEV(outp) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << outp)) == 0)
			continue;

		if (tx_buffers[outp].count == 0)
			continue;

		flush_one_port(&tx_buffers[outp], outp);
	}
}

static int
lcore_distributor(struct lcore_params *p)
{
	struct rte_ring *in_r = p->rx_dist_ring;
	struct rte_ring *out_r = p->dist_tx_ring;
	struct rte_mbuf *bufs[BURST_SIZE * 4];
	struct rte_distributor *d = p->d;

	printf("\nCore %u acting as distributor core.\n", rte_lcore_id());
	while (!quit_signal_dist) {
		const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
				(void *)bufs, BURST_SIZE*1, NULL);
		if (nb_rx) {
			/* Distribute the packets */
			rte_distributor_process(d, bufs, nb_rx);
			/* Handle Returns */
			const uint16_t nb_ret =
				rte_distributor_returned_pkts(d,
					bufs, BURST_SIZE*2);

			if (unlikely(nb_ret == 0))
				continue;

			uint16_t sent = rte_ring_enqueue_burst(out_r,
					(void *)bufs, nb_ret, NULL);
			if (unlikely(sent < nb_ret)) {
				RTE_LOG(DEBUG, DPDKDECODE,
					"%s:Packet loss due to full out ring\n",
					__func__);
				while (sent < nb_ret)
					rte_pktmbuf_free(bufs[sent++]);
			}
		}
	}
	printf("\nCore %u exiting distributor task.\n", rte_lcore_id());
	/* set tx threads quit flag */
	quit_signal_tx = 1;
	/* set worker threads quit flag */
	quit_signal_work = 1;
	rte_distributor_flush(d);
	/* Unblock any returns so workers can exit */
	rte_distributor_clear_returns(d);
	return 0;
}

static int
lcore_tx(struct rte_ring *in_r)
{
	static struct output_buffer tx_buffers[RTE_MAX_ETHPORTS];
	const int socket_id = rte_socket_id();
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0)
			continue;

		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) != socket_id)
			printf("WARNING, port %u is on remote NUMA node to "
					"TX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("\nCore %u doing packet TX.\n", rte_lcore_id());
	while (!quit_signal_tx) {

		RTE_ETH_FOREACH_DEV(port) {
			/* skip ports that are not enabled */
			if ((enabled_port_mask & (1 << port)) == 0)
				continue;

			struct rte_mbuf *bufs[BURST_SIZE_TX];
			const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
					(void *)bufs, BURST_SIZE_TX, NULL);

			/* if we get no traffic, flush anything we have */
			if (unlikely(nb_rx == 0)) {
				flush_all_ports(tx_buffers);
				continue;
			}

			/* for traffic we receive, queue it up for transmit */
			uint16_t i;
			rte_prefetch_non_temporal((void *)bufs[0]);
			rte_prefetch_non_temporal((void *)bufs[1]);
			rte_prefetch_non_temporal((void *)bufs[2]);
			for (i = 0; i < nb_rx; i++) {
				struct output_buffer *outbuf;
				uint8_t outp;
				rte_prefetch_non_temporal((void *)bufs[i + 3]);
				/*
				 * workers should update in_port to hold the
				 * output port value
				 */
				outp = bufs[i]->port;
				/* skip ports that are not enabled */
				if ((enabled_port_mask & (1 << outp)) == 0)
					continue;

				outbuf = &tx_buffers[outp];
				outbuf->mbufs[outbuf->count++] = bufs[i];
				if (outbuf->count == BURST_SIZE_TX)
					flush_one_port(outbuf, outp);
			}
		}
	}
	printf("\nCore %u exiting tx task.\n", rte_lcore_id());
	return 0;
}

static void
int_handler(int sig_num)
{
	printf("Exiting on signal %d\n", sig_num);
	/* set quit flag for rx thread to exit */
	quit_signal_rx = 1;
}

static int
lcore_worker(struct lcore_params *p)
{
	struct rte_distributor *d = p->d;
	const unsigned id = p->worker_id;
	unsigned int num = 0;
	unsigned int i;
	struct rte_mbuf *bufs[8] __rte_cache_aligned;
	struct rte_hash_parameters params = {0};
	char name[RTE_HASH_NAMESIZE];

	for (i = 0; i < 8; i++)
		bufs[i] = NULL;

	// Create a flow table for each worker
	params.entries = 1024 * 1024;
	params.key_len = sizeof(five_tuple);
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	params.socket_id = rte_socket_id();
	snprintf((char *)name, RTE_HASH_NAMESIZE, "flow_table_%d_%d", params.socket_id, rte_lcore_id());
	params.name = name;
	params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
	g_flow_tbl[rte_lcore_id()] = rte_hash_create(&params);
	if(unlikely(NULL == g_flow_tbl[rte_lcore_id()])) {
        printf("Failed to create flow table.\n");
        return -1;
    }
	printf("Creating flow table: %s\n", name);
	printf("\nCore %u acting as worker core.\n", rte_lcore_id());
	while (!quit_signal_work) {
		num = rte_distributor_get_pkt(d, id, bufs, bufs, num);
		/* decode for each packet */
		for (i = 0; i < num; i++) {
			five_tuple *tuple_info = rte_zmalloc("five_tuple", sizeof(five_tuple), RTE_CACHE_LINE_SIZE);
			uint8_t tcp_flags = 0;
			uint8_t *payload = NULL;
			cdr *cdr_info = NULL;
			// parser l2 to l4
			payload = parse_l2_to_l4_proto_info(bufs[i], tuple_info, &tcp_flags);
			if (tcp_flags & RTE_TCP_FIN_FLAG) {    // if close flow, delete flow table
				if (query_flow_table(g_flow_tbl[rte_lcore_id()], tuple_info, (void **)&cdr_info) >= 0) {
					// enqueue to output ring
					uint16_t send = rte_ring_enqueue_burst(p->worker_output_ring, (void *)&cdr_info, 1, NULL);
					delete_flow_table(g_flow_tbl[rte_lcore_id()], tuple_info);
				}
				rte_free(tuple_info);
				tuple_info = NULL;
				continue;
			}
			// add flow table
			if (unlikely(IPPROTO_TCP != tuple_info->proto_type && IPPROTO_UDP != tuple_info->proto_type)) {
				// do not insert flow table when the transport layer is not UDP or TCP
				rte_free(tuple_info);
				tuple_info = NULL;
				continue;
			}
			if (-1 == insert_flow_table(g_flow_tbl[rte_lcore_id()], tuple_info, (void **)&cdr_info)) {
				// do not insert flow table
				rte_free(tuple_info);
				tuple_info = NULL;
				continue;
			}
			// parser application protocol
			if (NULL == payload || 0 == strlen(payload)) {
				// if the payload is empty, do not parse.
				rte_free(tuple_info);
				tuple_info = NULL;
				continue;
			}
			if(parse_app_proto_info(payload, cdr_info) >= 0) {
				// update flow table
				update_flow_table(g_flow_tbl[rte_lcore_id()], tuple_info, cdr_info);
			}
		}
	}
	/* set flow table age threads quit flag */
	quit_signal_flow_tbl_age = 1;
	/* set output threads quit flag */
	quit_signal_output = 1;
	rte_free(p);
	rte_hash_free(g_flow_tbl[rte_lcore_id()]);    // free flow table
	return 0;
}

// flow table age
static int
lcore_flow_table_age(struct rte_ring *work_output_ring)
{
	five_tuple *tuple_info = NULL;
	cdr *cdr_info = NULL;
	uint32_t iter = 0;
	struct timespec ts = {0};
	int i = 0;
	// declare the tail queue head
	TAILQ_HEAD(key_head, key_to_delete); 
	printf("\nCore %u doing flow table age.\n", rte_lcore_id());
	while (!quit_signal_flow_tbl_age) {
		/* iterate through the hash table */
		for (i = 0; i < RTE_DIM(g_flow_tbl); i++) {
			struct key_head keys = TAILQ_HEAD_INITIALIZER(keys);
			tuple_info = NULL;
			cdr_info = NULL;
			iter = 0;
			memset(&ts, 0, sizeof(ts));
			if (NULL == g_flow_tbl[i]) {
				continue;
			}
			while (rte_hash_iterate(g_flow_tbl[i], (const void **)&tuple_info, (void **)&cdr_info, &iter) >= 0) {
				clock_gettime(CLOCK_REALTIME, &ts);
				if (ts.tv_sec - cdr_info->timestamp.tv_sec > FLOW_TABLE_AGE_SEC) {
					// record the keys that need to be deleted
					key_to_delete_t *key = rte_zmalloc("key_to_delete_t", sizeof(key_to_delete_t), RTE_CACHE_LINE_SIZE);
					if (unlikely(NULL == key)) {
						printf("[%s][%s][line %d] Memory allocation failed for key!\n",__FILE__,__func__,__LINE__);
						continue;
					}
					key->tuple = tuple_info;
					TAILQ_INSERT_TAIL(&keys, key, next);
					// enqueue to output ring
					uint16_t send = rte_ring_enqueue_burst(work_output_ring, (void *)&cdr_info, 1, NULL);
				}
			}
			// after traversing, delete according to the recorded keys
			key_to_delete_t *cur = NULL;
			while (!TAILQ_EMPTY(&keys)) {
        		cur = TAILQ_FIRST(&keys);
				delete_flow_table(g_flow_tbl[i], cur->tuple);
        		TAILQ_REMOVE(&keys, cur, next);
				//rte_free(cur->tuple);    // insert flow table when allocat memory on the heap
				cur->tuple = NULL;
        		rte_free(cur);
				cur = NULL;
    		}
		}
		// wait 10s
		sleep(10);
	}
	printf("\nCore %u exiting flow table age task.\n", rte_lcore_id());
	return 0;
}

// call detail record
static int
lcore_output(struct rte_ring *work_output_ring)
{
	cdr *cdr_info = NULL;
	uint16_t nb_rx = 0;
	printf("\nCore %u doing call detail record output.\n", rte_lcore_id());
	while (!quit_signal_output) {
		nb_rx = rte_ring_dequeue_burst(work_output_ring, (void *)&cdr_info, 1, NULL);
		if (nb_rx) {
			cdr_output(cdr_info);
			rte_free(cdr_info);              // insert flow table when allocat memory on the heap
			cdr_info = NULL;
		}
	}
	printf("\nCore %u exiting output task.\n", rte_lcore_id());
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK\n"
			"  -p PORTMASK: hexadecimal bitmask of ports to configure\n",
			prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, "p:",
			lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind <= 1) {
		print_usage(prgname);
		return -1;
	}

	argv[optind-1] = prgname;

	optind = 1; /* reset getopt lib */
	return 0;
}

/* Main function, does initialization and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	struct rte_distributor *d;
	struct rte_ring *dist_tx_ring;
	struct rte_ring *rx_dist_ring;
	struct rte_ring *worker_output_ring;
	unsigned int lcore_id, worker_id = 0;
	int rx_core_id = -1, tx_core_id = -1, flow_tbl_age_core_id = -1, output_core_id = -1;
	unsigned nb_ports;
	unsigned int min_cores;
	uint16_t portid;
	uint16_t nb_ports_available;
	uint64_t t, freq;

	/* catch ctrl-c so we can print on exit */
	signal(SIGINT, int_handler);

	/* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid dpdkDecode parameters\n");

	min_cores = 5;
	num_workers = rte_lcore_count() - 4;

	if (rte_lcore_count() < min_cores)
		rte_exit(EXIT_FAILURE, "Error, This application needs at "
				"least 6 logical cores to run:\n"
				"1 lcore for distribution (can be core 0)\n"
				"1 lcore for packet RX\n"
				"1 lcore for packet TX\n"
				"1 lcore for flow table age\n"
				"1 lcore for output information\n"
				"and at least 1 lcore for worker threads\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no ethernet ports detected\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	nb_ports_available = nb_ports;

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... done\n", portid);

		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialize port %u\n",
					portid);
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
				"All available ports are disabled. Please set portmask.\n");
	}

	// Create a distributor for packages
	d = rte_distributor_create("PKT_DIST", rte_socket_id(),
			num_workers,
			RTE_DIST_ALG_BURST);
	if (d == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create distributor\n");

	/*
	 * scheduler ring is read by the transmitter core, and written to
	 * by scheduler core
	 */
	dist_tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (dist_tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	rx_dist_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_dist_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	// Message queue ring for worker thread and output thread
	worker_output_ring = rte_ring_create("worker_output_ring", MSG_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);

	/*
	 * If there's any of the key workloads left without an lcore_id
	 * after the high performing core assignment above, pre-assign
	 * them here.
	 */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (lcore_id == (unsigned int)rx_core_id ||
				lcore_id == (unsigned int)tx_core_id ||
				lcore_id == (unsigned int)flow_tbl_age_core_id ||
				lcore_id == (unsigned int)output_core_id)
			continue;
		if (rx_core_id < 0) {
			rx_core_id = lcore_id;
			printf("Rx on core %d\n", lcore_id);
			continue;
		}
		if (tx_core_id < 0) {
			tx_core_id = lcore_id;
			printf("Tx on core %d\n", lcore_id);
			continue;
		}
		if (flow_tbl_age_core_id < 0) {
			flow_tbl_age_core_id = lcore_id;
			printf("flow table age on core %d\n", lcore_id);
			continue;
		}
		if (output_core_id < 0) {
			output_core_id = lcore_id;
			printf("output on core %d\n", lcore_id);
			continue;
		}
	}

	/*
	 * Kick off all the worker threads first, avoiding the pre-assigned
	 * lcore_ids for tx, rx and output workloads.
	 */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (lcore_id == (unsigned int)rx_core_id ||
				lcore_id == (unsigned int)tx_core_id ||
				lcore_id == (unsigned int)flow_tbl_age_core_id ||
				lcore_id == (unsigned int)output_core_id)
			continue;
		printf("Starting thread %d as worker, lcore_id %d\n",
				worker_id, lcore_id);
		struct lcore_params *p =
			rte_malloc(NULL, sizeof(*p), 0);
		if (!p)
			rte_panic("malloc failure\n");
		*p = (struct lcore_params){worker_id++, d, rx_dist_ring,
			dist_tx_ring, worker_output_ring, mbuf_pool};

		rte_eal_remote_launch((lcore_function_t *)lcore_worker,
				p, lcore_id);
	}

	/* Start rx core */
	struct lcore_params *pr =
		rte_malloc(NULL, sizeof(*pr), 0);
	if (!pr)
		rte_panic("malloc failure\n");
	*pr = (struct lcore_params){worker_id++, d, rx_dist_ring,
		dist_tx_ring, NULL, mbuf_pool};
	rte_eal_remote_launch((lcore_function_t *)lcore_rx,
			pr, rx_core_id);

	/* Start tx core */
	rte_eal_remote_launch((lcore_function_t *)lcore_tx,
			dist_tx_ring, tx_core_id);

	/* Start flow table age */
	rte_eal_remote_launch((lcore_function_t *)lcore_flow_table_age,
			worker_output_ring, flow_tbl_age_core_id);
	
	/* Start output core */
	rte_eal_remote_launch((lcore_function_t *)lcore_output,
			worker_output_ring, output_core_id);

	/* Call distributor on main core */
	struct lcore_params *pd = NULL;
	pd = rte_malloc(NULL, sizeof(*pd), 0);
	if (!pd)
		rte_panic("malloc failure\n");
	*pd = (struct lcore_params){worker_id++, d,
		rx_dist_ring, dist_tx_ring, NULL, mbuf_pool};
	lcore_distributor(pd);

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	rte_free(pd);
	rte_free(pr);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
