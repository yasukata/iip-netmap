/*
 *
 * Copyright 2024 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <sys/ioctl.h>
#include <sys/poll.h>

#include <net/ethernet.h>

#include <pthread.h>

#include <libnetmap.h>

#if defined(__linux__)
#include <sched.h>
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#include <sys/cpuset.h>
#define cpu_set_t cpuset_t
#endif

#define __IOSUB_MAX_CORE (256)

#ifndef NUM_RX_DESC
#define NUM_RX_DESC (128)
#endif
#ifndef NUM_TX_DESC
#define NUM_TX_DESC NUM_RX_DESC
#endif
#define NUM_BUF (4096 > ((NUM_RX_DESC + NUM_TX_DESC) * 4) ? 4096 : ((NUM_RX_DESC + NUM_TX_DESC) * 4))
#ifndef NUM_NETSTACK_PB
#define NUM_NETSTACK_PB (8192)
#endif
#ifndef NUM_NETSTACK_TCP_CONN
#define NUM_NETSTACK_TCP_CONN (512)
#endif
#ifndef ETH_RX_BATCH
#define ETH_RX_BATCH (32)
#endif
#ifndef ETH_TX_BATCH
#define ETH_TX_BATCH ETH_RX_BATCH
#endif
#define ETH_TX_CHAIN_MAX (16)
#if (NUM_TX_DESC < ETH_TX_BATCH + ETH_TX_CHAIN_MAX) /* avoid exceeding limit in eth push / flush */
#error "too large max chain and batch"
#endif

#define __NUM_BUF_DOUBLE (NUM_BUF * 2 * __IOSUB_MAX_CORE)
#define __IOSUB_BUF_ASSERT(__iop, __buf_idx) do { assert((__buf_idx) < (__NUM_BUF_DOUBLE)); } while (0)
#define __IOSUB_BUF_REFCNT(__iop, __buf_idx) ((__iop)->netmap.buf_ref[__buf_idx])

struct __npb {
	uint32_t buf_idx;
	uint16_t len;
	uint16_t head;
	struct __npb *next[2];
	struct __npb *prev[2];
};

struct io_opaque {
	uint16_t core_id;
	struct {
		struct nmport_d *nmd;
		uint16_t buf_ref[__NUM_BUF_DOUBLE];
		uint32_t free_buf_cnt;
		uint32_t free_buf_idx[NUM_BUF];
		struct {
			uint32_t free_cnt;
			struct __npb *free_p[NUM_NETSTACK_PB];
			struct __npb p[NUM_NETSTACK_PB];
		} pool;
		uint16_t eth_sent;
	} netmap;
	struct {
		struct {
			struct __npb *m[ETH_TX_BATCH];
			uint16_t cnt;
			uint16_t num_pkt;
		} tx;
	} eth;
	struct {
		struct {
			uint64_t rx_pkt;
			uint64_t rx_drop;
			uint64_t tx_pkt;
			uint64_t tx_fail;
		} eth;
	} stat[2];
};

static _Atomic uint8_t stat_idx = 0;

static uint8_t mac_addr[6] = { 0 };
static uint32_t ip4_addr_be = 0;
static struct io_opaque io_opaque[__IOSUB_MAX_CORE] = { 0 };

static struct nmport_d *__iosub_nmd = NULL;
static const char *__iosub_ifname = NULL;
static uint16_t __iosub_num_cores = 0;
static uint16_t __iosub_core_list[__IOSUB_MAX_CORE];

static int32_t __iosub_max_poll_wait_ms = 1000U; /* 1 sec */

static uint16_t helper_ip4_get_connection_affinity(uint16_t protocol, uint32_t local_ip4_be, uint16_t local_port_be, uint32_t peer_ip4_be, uint16_t peer_port_be, void *opaque)
{
	return 0;
	{ /* unused */
		(void) protocol;
		(void) local_ip4_be;
		(void) local_port_be;
		(void) peer_ip4_be;
		(void) peer_port_be;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	return sizeof(struct ether_header);
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint8_t *iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	return ((struct ether_header *)(iip_ops_pkt_get_data(pkt, opaque)))->ether_shost;
}

static uint8_t *iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	return ((struct ether_header *)(iip_ops_pkt_get_data(pkt, opaque)))->ether_dhost;
}

static uint8_t iip_ops_l2_skip(void *pkt, void *opaque)
{
	return 0;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	return ((struct ether_header *)(iip_ops_pkt_get_data(pkt, opaque)))->ether_type;
}

static uint16_t iip_ops_l2_addr_len(void *opaque)
{
	return 6;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_l2_broadcast_addr(uint8_t bc_mac[], void *opaque)
{
	memset(bc_mac, 0xff, 6);
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
{
	struct ether_header *ethh = (struct ether_header *) iip_ops_pkt_get_data(pkt, opaque);
	memcpy(ethh->ether_shost, src, 6);
	memcpy(ethh->ether_dhost, dst, 6);
	ethh->ether_type = ethertype_be;
}

static uint8_t iip_ops_arp_lhw(void *opaque)
{
	return 6;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_arp_lproto(void *opaque)
{
	return 4;
	{ /* unused */
		(void) opaque;
	}
}

static void __iip_buf_free(uint32_t buf_idx, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	__IOSUB_BUF_ASSERT(iop, buf_idx);
	if (--__IOSUB_BUF_REFCNT(iop, buf_idx) == 0)
		iop->netmap.free_buf_idx[iop->netmap.free_buf_cnt++] = buf_idx;
}

static uint32_t __iip_buf_alloc(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	if (iop->netmap.free_buf_cnt) {
		uint32_t buf_idx = iop->netmap.free_buf_idx[--iop->netmap.free_buf_cnt];
		__IOSUB_BUF_ASSERT(iop, buf_idx);
		assert(++__IOSUB_BUF_REFCNT(iop, buf_idx) == 1);
		return buf_idx;
	} else
		return UINT32_MAX;
}

static void *__iip_ops_pkt_alloc(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	assert(iop->netmap.pool.free_cnt);
	{
		struct __npb *p = iop->netmap.pool.free_p[--iop->netmap.pool.free_cnt];
		assert(p);
		return (void *) p;
	}
}

static void *iip_ops_pkt_alloc(void *opaque)
{
	struct __npb *p = __iip_ops_pkt_alloc(opaque);
	p->buf_idx = __iip_buf_alloc(opaque);
	assert(p->buf_idx != UINT32_MAX);
	p->len = 0;
	p->head = 0;
	return p;
}

static void __iip_pkt_free(void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	assert(iop->netmap.pool.free_cnt < NUM_NETSTACK_PB);
	iop->netmap.pool.free_p[iop->netmap.pool.free_cnt++] = pkt;
}

static void iip_ops_pkt_free(void *pkt, void *opaque)
{
	assert(pkt);
	__iip_buf_free(((struct __npb *) pkt)->buf_idx, opaque);
	__iip_pkt_free(pkt, opaque);
}

static void *iip_ops_pkt_get_data(void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (void *) ((uintptr_t) NETMAP_BUF(NETMAP_RXRING(iop->netmap.nmd->nifp, iop->core_id), ((struct __npb *) pkt)->buf_idx) + ((struct __npb *) pkt)->head);
}

static uint16_t iip_ops_pkt_get_len(void *pkt, void *opaque __attribute__((unused)))
{
	return ((struct __npb *) pkt)->len;
}

static void iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque __attribute__((unused)))
{
	assert(pkt);
	((struct __npb *) pkt)->len = len;
}

static void iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque __attribute__((unused)))
{
	assert(pkt);
	assert(len <= ((struct __npb *) pkt)->len);
	((struct __npb *) pkt)->head += len;
	((struct __npb *) pkt)->len -= len;
}

static void iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque __attribute__((unused)))
{
	assert(pkt);
	assert(len <= ((struct __npb *) pkt)->len);
	((struct __npb *) pkt)->len -= len;
}

static void *iip_ops_pkt_clone(void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	__IOSUB_BUF_ASSERT(iop, ((struct __npb *) pkt)->buf_idx);
	assert(__IOSUB_BUF_REFCNT(iop, ((struct __npb *) pkt)->buf_idx));
	{
		struct __npb *p = __iip_ops_pkt_alloc(opaque);
		p->buf_idx = ((struct __npb *) pkt)->buf_idx;
		p->len = ((struct __npb *) pkt)->len;
		p->head = ((struct __npb *) pkt)->head;
		__IOSUB_BUF_REFCNT(iop, ((struct __npb *) pkt)->buf_idx)++;
		return p;
	}
}

static void iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque __attribute__((unused)))
{
	struct __npb *p = (struct __npb *) pkt_head;
	while (p->next[1])
		p = p->next[1];
	p->next[1] = pkt_tail;
	((struct __npb *) pkt_tail)->next[1] = NULL;
}

static void *iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque __attribute__((unused)))
{
	return ((struct __npb *) pkt_head)->next[0];
}

static void iip_ops_l2_flush(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	if (iop->eth.tx.num_pkt) {
		{
			struct netmap_ring *tx_ring = NETMAP_TXRING(iop->netmap.nmd->nifp, iop->core_id);
			{
				uint32_t i = 0;
				{
					uint32_t j_prev = 0, j = tx_ring->head, k = tx_ring->tail;
					while (nm_ring_next(tx_ring, j) != k && i < iop->eth.tx.num_pkt) {
						__iip_buf_free(tx_ring->slot[j].buf_idx, opaque);
						tx_ring->slot[j].buf_idx = iop->eth.tx.m[i]->buf_idx;
						tx_ring->slot[j].len = iop->eth.tx.m[i]->len;
						tx_ring->slot[j].ptr = iop->eth.tx.m[i]->head;
						tx_ring->slot[j].flags |= NS_BUF_CHANGED;
						__iip_pkt_free(iop->eth.tx.m[i], opaque);
						i++;
						j_prev = j;
						j = nm_ring_next(tx_ring, j);
					}
					if (i)
						tx_ring->slot[j_prev].flags |= NS_REPORT;
					tx_ring->head = tx_ring->cur = j;
					assert(!ioctl(iop->netmap.nmd->fd, NIOCTXSYNC, NULL));
				}
				if (i != iop->eth.tx.cnt) {
					uint32_t j;
					for (j = i; j < iop->eth.tx.cnt; j++)
						iip_ops_pkt_free(iop->eth.tx.m[j], opaque);
				}
				iop->stat[stat_idx].eth.tx_pkt += i;
			}
		}
		iop->eth.tx.cnt = iop->eth.tx.num_pkt = 0;
	}
}

static void iip_ops_l2_push(void *_m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	{
		struct __npb *p = (struct __npb *) _m;
		while (p) {
			iop->eth.tx.m[iop->eth.tx.cnt++] = (struct __npb *) p;
			p = p->next[1];
		}
		iop->eth.tx.num_pkt++;
	}
	if (ETH_TX_BATCH <= iop->eth.tx.cnt || iop->eth.tx.cnt == nm_ring_space(NETMAP_TXRING(iop->netmap.nmd->nifp, iop->core_id)) - 1)
		iip_ops_l2_flush(opaque);
}

static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static volatile uint16_t setup_core_id = 0;

struct __thread_info {
	pthread_t th;
	uint16_t id;
	void *app_global_opaque;
};

/* thread loop */
static void *__thread_fn(void *__data)
{
	struct __thread_info *ti = (struct __thread_info *) __data;
	{
		cpu_set_t cs;
		CPU_ZERO(&cs);
		CPU_SET(ti->id, &cs);
		assert(pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs) == 0);
	}

	while (ti->id != setup_core_id)
		usleep(10000);

	{
		void *workspace = calloc(1, iip_workspace_size());
		assert(workspace);
		{
			uint8_t *_premem[2];
			{
				assert((_premem[0] = (uint8_t *) calloc(1, iip_pb_size() * NUM_NETSTACK_PB)) != NULL);
				{ /* associate memory for packet representation structure */
					uint32_t i;
					for (i = 0; i < NUM_NETSTACK_PB; i++)
						iip_add_pb(workspace, &_premem[0][i * iip_pb_size()]);
				}
				assert((_premem[1] = calloc(1, iip_tcp_conn_size() * NUM_NETSTACK_TCP_CONN)) != NULL);
				{ /* associate memory for tcp connection */
					uint16_t i;
					for (i = 0; i < NUM_NETSTACK_TCP_CONN; i++)
						iip_add_tcp_conn(workspace, &_premem[1][i * iip_tcp_conn_size()]);
				}
				{ /* associate memory for tcp connection */
					uint16_t i;
					for (i = 0; i < NUM_NETSTACK_PB; i++)
						io_opaque[ti->id].netmap.pool.free_p[io_opaque[ti->id].netmap.pool.free_cnt++] = &io_opaque[ti->id].netmap.pool.p[i];
				}
				io_opaque[ti->id].core_id = ti->id;
				if (!ti->id) {
					assert(!__iosub_nmd);
					assert((io_opaque[ti->id].netmap.nmd = __iosub_nmd = nmport_prepare(__iosub_ifname)) != NULL);
					io_opaque[ti->id].netmap.nmd->reg.nr_rx_slots = NUM_RX_DESC;
					io_opaque[ti->id].netmap.nmd->reg.nr_tx_slots = NUM_TX_DESC;
					io_opaque[ti->id].netmap.nmd->reg.nr_rx_rings = io_opaque[ti->id].netmap.nmd->reg.nr_tx_rings = __iosub_num_cores;
					io_opaque[ti->id].netmap.nmd->reg.nr_extra_bufs = NUM_BUF - NUM_RX_DESC - NUM_TX_DESC;
					io_opaque[ti->id].netmap.nmd->reg.nr_mode = NR_REG_ONE_NIC;
					/* io_opaque[ti->id].netmap.nmd->reg.nr_flags |= NR_ACCEPT_VNET_HDR; */
				} else {
					assert(__iosub_nmd);
					assert((io_opaque[ti->id].netmap.nmd = nmport_clone(__iosub_nmd)) != NULL);
				}
				io_opaque[ti->id].netmap.nmd->reg.nr_ringid = ti->id & NETMAP_RING_MASK;
				assert(nmport_open_desc(io_opaque[ti->id].netmap.nmd) >= 0);

				setup_core_id++;

				{ /* call app thread init */
					void *opaque[3] = { (void *) &io_opaque[ti->id], ti->app_global_opaque, NULL, };
					{ /* reference count setting for buffers associated with the ring */
						struct netmap_ring *rx_ring = NETMAP_RXRING(io_opaque[ti->id].netmap.nmd->nifp, ti->id);
						{
							uint32_t i;
							for (i = 0; i < rx_ring->num_slots; i++)
								io_opaque[ti->id].netmap.buf_ref[rx_ring->slot[i].buf_idx] = 1;
						}
					}
					{ /* reference count setting for buffers associated with the ring */
						struct netmap_ring *tx_ring = NETMAP_TXRING(io_opaque[ti->id].netmap.nmd->nifp, ti->id);
						{
							uint32_t i;
							for (i = 0; i < tx_ring->num_slots; i++)
								io_opaque[ti->id].netmap.buf_ref[tx_ring->slot[i].buf_idx] = 1;
						}
					}
					{ /* add reference and release; the buffers assocaited with the rings will not be reclaimed */
						uint32_t j, k;
						for (j = 0, k = io_opaque[ti->id].netmap.nmd->nifp->ni_bufs_head; k; j++, k = *(uint32_t *)(NETMAP_BUF(NETMAP_RXRING(io_opaque[ti->id].netmap.nmd->nifp, ti->id), k))) {
							assert(j < NUM_BUF);
							io_opaque[ti->id].netmap.buf_ref[k] = 1;
							__iip_buf_free(k, opaque);
						}
					}
					{
						opaque[2] = __app_thread_init(workspace, ti->id, opaque);
						{
							uint64_t prev_print = 0;
							do {
								uint32_t next_us = __iosub_max_poll_wait_ms * 1000;
								{
									struct __npb *m[ETH_RX_BATCH] = { 0 };
									uint32_t cnt = 0;
									{
										struct netmap_ring *rx_ring = NETMAP_RXRING(io_opaque[ti->id].netmap.nmd->nifp, ti->id);
										{
											uint32_t i = 0, j = rx_ring->head, k = rx_ring->tail;
											while (i < ETH_RX_BATCH && j != k) {
												__IOSUB_BUF_ASSERT(&io_opaque[ti->id], rx_ring->slot[j].buf_idx);
												assert(__IOSUB_BUF_REFCNT(&io_opaque[ti->id], rx_ring->slot[j].buf_idx) == 1);
												assert((m[i] = __iip_ops_pkt_alloc(opaque)) != NULL);
												m[i]->buf_idx = rx_ring->slot[j].buf_idx;
												m[i]->len = rx_ring->slot[j].len;
												m[i]->head = rx_ring->slot[j].ptr;
												rx_ring->slot[j].buf_idx = __iip_buf_alloc(opaque);
												assert(rx_ring->slot[j].buf_idx != UINT32_MAX);
												rx_ring->flags |= NS_BUF_CHANGED;
												cnt++;
												i++;
												j = nm_ring_next(rx_ring, j);
											}
											rx_ring->head = rx_ring->cur = j;
										}
									}
									if (cnt)
										io_opaque[ti->id].stat[stat_idx].eth.rx_pkt += cnt;
									if (cnt)
										next_us = 0;
									{ /* execute network stack */
										uint32_t _next_us = 1000000U;
										iip_run(workspace, mac_addr, ip4_addr_be, (void **) m, cnt, &_next_us, opaque);
										next_us = _next_us < next_us ? _next_us : next_us;
									}
								}
								{
									uint32_t _next_us = 1000000U;
									__app_loop(workspace, mac_addr, ip4_addr_be, &_next_us, opaque);
									next_us = _next_us < next_us ? _next_us : next_us;
								}
								if (!ti->id) {
									struct timespec ts;
									assert(!clock_gettime(CLOCK_REALTIME, &ts));
									if (prev_print + 1000000000UL < ts.tv_sec * 1000000000UL + ts.tv_nsec) {
#if 0
										stat_idx = (stat_idx ? 0 : 1);
										asm volatile ("" ::: "memory");
										{
											uint64_t total_rx = 0, total_tx = 0;
											{
												uint16_t i;
												for (i = 0; i < __iosub_num_cores; i++) {
													printf("\x1b[33mqueue[%u]: rx %lu drop %lu tx %lu fail %lu\n\x1b[39m",
															i,
															io_opaque[i].stat[stat_idx ? 0 : 1].eth.rx_pkt,
															io_opaque[i].stat[stat_idx ? 0 : 1].eth.rx_drop,
															io_opaque[i].stat[stat_idx ? 0 : 1].eth.tx_pkt,
															io_opaque[i].stat[stat_idx ? 0 : 1].eth.tx_fail);
													total_rx += io_opaque[i].stat[stat_idx ? 0 : 1].eth.rx_pkt;
													total_tx += io_opaque[i].stat[stat_idx ? 0 : 1].eth.tx_pkt;
													memset(&io_opaque[i].stat[stat_idx ? 0 : 1], 0, sizeof(io_opaque[i].stat[stat_idx ? 0 : 1]));
												}
											}
											printf("\x1b[33meth total: rx %lu tx %lu\n\x1b[39m", total_rx, total_tx);
										}
#endif
										prev_print = ts.tv_sec * 1000000000UL + ts.tv_nsec;
									}
								}
								{
									struct pollfd pollfd = {
										.fd = io_opaque[ti->id].netmap.nmd->fd,
										.events = POLLIN,
									};
									assert(poll(&pollfd, 1, (next_us / 1000)) != -1);
								}
							} while (!__app_should_stop(opaque));
						}
					}
				}
				nmport_close(io_opaque[ti->id].netmap.nmd);
			}
			free(_premem[1]);
			free(_premem[0]);
		}
		free(workspace);
	}

	pthread_exit(NULL);
}

static int __iosub_main(int argc, char *const *argv)
{
	{
		int ch;
		while ((ch = getopt(argc, argv, "a:e:i:l:")) != -1) {
			switch (ch) {
			case 'a':
				{ /* format: mac,ip (e.g., ab:cd:ef:01:23:45,192.168.0.1 */
					char tmpbuf[64] = { 0 };
					size_t l = strlen(optarg);
					assert(l < (sizeof(tmpbuf) - 1));
					memcpy(tmpbuf, optarg, l);
					{
						size_t i;
						for (i = 0; i < l; i++) {
							if (tmpbuf[i] == ',') {
								tmpbuf[i] = '\0';
								sscanf(tmpbuf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
										&mac_addr[0],
										&mac_addr[1],
										&mac_addr[2],
										&mac_addr[3],
										&mac_addr[4],
										&mac_addr[5]);
								assert(inet_pton(AF_INET, &tmpbuf[i + 1], &ip4_addr_be) == 1);
								break;
							}
						}
						assert(i != 0 && i != l);
						printf("address %02x:%02x:%02x:%02x:%02x:%02x %u.%u.%u.%u\n",
								mac_addr[0],
								mac_addr[1],
								mac_addr[2],
								mac_addr[3],
								mac_addr[4],
								mac_addr[5],
								(ip4_addr_be >>  0) & 0xff,
								(ip4_addr_be >>  8) & 0xff,
								(ip4_addr_be >> 16) & 0xff,
								(ip4_addr_be >> 24) & 0xff);
					}
				}
				break;
			case 'e':
				assert(sscanf(optarg, "%d", &__iosub_max_poll_wait_ms) == 1);
				break;
			case 'i':
				__iosub_ifname = optarg;
				break;
			case 'l':
				{
					ssize_t num_comma = 0, num_hyphen = 0;
					{
						size_t i;
						for (i = 0; i < strlen(optarg); i++) {
							switch (optarg[i]) {
							case ',':
								num_comma++;
								break;
							case '-':
								num_hyphen++;
								break;
							}
						}
					}
					if (num_hyphen) {
						assert(num_hyphen == 1);
						assert(!num_comma);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i;
								for (i = 0; i < strlen(optarg); i++) {
									if (m[i] == '-') {
										m[i] = '\0';
										break;
									}
								}
								assert(i != strlen(optarg) - 1 && i != strlen(optarg));
								{
									uint16_t from = atoi(&m[0]), to = atoi(&m[i + 1]);
									assert(from < to);
									{
										uint16_t j, k;
										for (j = 0, k = from; k <= to; j++, k++)
											__iosub_core_list[j] = k;
										__iosub_num_cores = j;
									}
								}
							}
							free(m);
						}
					} else if (num_comma) {
						assert(num_comma + 1 < __IOSUB_MAX_CORE);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i, j, k;
								for (i = 0, j = 0, k = 0; i < strlen(optarg) + 1; i++) {
									if (i == strlen(optarg) || m[i] == ',') {
										m[i] = '\0';
										if (j != i)
											__iosub_core_list[k++] = atoi(&m[j]);
										j = i + 1;
									}
									if (i == strlen(optarg))
										break;
								}
								assert(k);
								__iosub_num_cores = k;
							}
							free(m);
						}
					} else {
						__iosub_core_list[0] = atoi(optarg);
						__iosub_num_cores = 1;
					}
				}
				break;
			default:
				assert(0);
				break;
			}
		}
	}

	assert(__iosub_ifname);
	assert(0 < __iosub_num_cores && __iosub_num_cores < MAX_THREAD);

	{
		uint16_t i;
		for (i = 0; i < __iosub_num_cores; i++) {
			printf("core map[%u]: %u\n", i, __iosub_core_list[i]);
		}
	}

	{
		void *app_global_opaque = __app_init(argc, argv);
		{
			struct __thread_info ti[MAX_THREAD];
			{
				uint16_t i;
				for (i = 0; i < __iosub_num_cores; i++) {
					ti[i].id = i;
					ti[i].app_global_opaque = app_global_opaque;
					assert(!pthread_create(&ti[i].th, NULL, __thread_fn, &ti[i]));
				}
			}
			{
				uint16_t i;
				for (i = 0; i < __iosub_num_cores; i++)
					assert(!pthread_join(ti[i].th, NULL));
			}
		}
		__app_exit(app_global_opaque);
	}

	printf("Done.\n");

	return 0;
}
