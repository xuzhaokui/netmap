/*
 * Copyright (C) 2014 Vincenzo Maffione. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>

static int veth_open(struct ifnet *ifp);
static int veth_close(struct ifnet *ifp);

// 在 netmap 中注册/注销这个 veth 设备（这一步发生在用 netmap mode 打开/关闭 veth 的时候）
// 其实是打开/关闭了对应 adapter 中 netmap 相关标记位，以及替换/还原了 veth 的 netdev_ops 函数集
/*
 * Register/unregister. We are already under netmap lock.
 */
static int
veth_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	bool was_up = false;
	enum txrx t;
	int i;

	if (na->active_fds > 0) {
		/* No support for single-queue mode. Actually do something
		 * only for first user and last user. */
		return 0;
	}

	if (netif_running(ifp)) {
		/* The interface is up. Close it while (un)registering. */
		was_up = true;
		veth_close(ifp);
	}

	/* Enable or disable flags and callbacks in na and ifp. */
	if (onoff) {
		// 这一步是关联 veth 和 netmap 的关键：
		// * 其中替换了 veth 的 netdev_ops 为 netmap 的函数集，使得协议栈会通过 netmap 的 netdev_ops 来在 veth 上收发包
		nm_set_native_flags(na);
	} else {
		// 还原 veth device 的 netdev_ops 钩子函数
		nm_clear_native_flags(na);
	}

	// 设置 ring 的开关
	//
	/* Set or clear nr_pending_mode and nr_mode, independently of the
	 * state of nr_pending_mode. */
	for_rx_tx(t) {
		for (i = 0; i < nma_get_nrings(na, t); i++) {
			struct netmap_kring *kring = &NMR(na, t)[i];
			kring->nr_mode = kring->nr_pending_mode =
				onoff ? NKR_NETMAP_ON : NKR_NETMAP_OFF;
		}
	}

	if (was_up)
		// 最后一步是打开 veth
		veth_open(ifp);

	return (0);
}

// txsync 一般用于将 txring 中的数据发送到底层链路上（或者交换机），
// 但对于 veth 来说，发送过程实际上只是将数据放到对端 Peer veth 的 rxring 中即可
//
// 从 veth0 的 txring 中拿出数据放到 veth1 的 rxring 中
//
/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
veth_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct veth_priv *priv = netdev_priv(ifp);
	struct net_device *peer_ifp;
	struct netmap_adapter *peer_na;
	struct netmap_kring *peer_kring;
	struct netmap_ring *peer_ring;
	u_int nm_j;
	u_int peer_hwtail_lim;
	u_int lim_peer;

	rcu_read_lock();

	if (unlikely(!netif_carrier_ok(ifp)))
		goto out;

	peer_ifp = rcu_dereference(priv->peer);
	if (unlikely(!peer_ifp))
		goto out;

	peer_na = NA(peer_ifp); // 从 *net_device 获取 adapter
	if (unlikely(!nm_netmap_on(peer_na))) // 确定 peer veth 的 netmap mode 打开
		goto out;

	/* XXX This is unsafe, we are accessing the peer whose krings
	 * and rings may be disappearing beause peer_na->active_fds
	 * the last user is doing unregif. Is it feasible to call
	 * netamp_do_regif() on the peer in veth_netmap_reg()?. */
	peer_kring = &peer_na->rx_rings[ring_nr];
	if (!peer_kring) {
		goto out;
	}

	peer_ring = peer_kring->ring;
	lim_peer = peer_kring->nkr_num_slots - 1;

	/*
	 * First part: process new packets to send.
	 */
	nm_i = kring->nr_hwcur; // (veth0's tx ring) kernel 当前完成发送的位置
	nm_j = peer_kring->nr_hwtail; // (veth1's rx ring) kernel 当前填入、可供用户使用的最后位置

	mb();  /* for reading peer_kring->nr_hwcur */
	peer_hwtail_lim = nm_prev(peer_kring->nr_hwcur, lim_peer);
	if (nm_i != head) {	/* we have new packets to send */
		for (n = 0; nm_i != head && nm_j != peer_hwtail_lim; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			struct netmap_slot tmp;
			void *addr = NMB(na, slot);

			/* device specific */
			struct netmap_slot *peer_slot = &peer_ring->slot[nm_j];

			NM_CHECK_ADDR_LEN(na, addr, len);

			// 从 veth0's txring 拿出 slot 与 veth1's rxring 中空闲 slot 交换指针
			tmp = *slot;
			*slot = *peer_slot;
			*peer_slot = tmp;

			nm_i = nm_next(nm_i, lim);
			nm_j = nm_next(nm_j, lim_peer);
		}
		kring->nr_hwcur = nm_i;

		smp_mb();  /* for writing the slots */

		// 传送完数据之后，更新游标
		peer_kring->nr_hwtail = nm_j;
		if (peer_kring->nr_hwtail > lim_peer) {
			peer_kring->nr_hwtail -= lim_peer + 1;
		}

		smp_mb();  /* for writing peer_kring->nr_hwtail */

		/*
		 * Second part: reclaim buffers for completed transmissions.
		 */
		kring->nr_hwtail += n;
		if (kring->nr_hwtail > lim)
			kring->nr_hwtail -= lim + 1;

		// 通知阻塞进程去继续读/写
		peer_kring->nm_notify(peer_kring, 0);
	}
out:
	rcu_read_unlock();

	return 0;
}


// 从 veth0 的 rxring 中拿出数据放到 veth1 的 txring 中
// 但实际不用做实际交换，因为 veth1 的 txsync 已经做了相同的交换
/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
veth_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
	struct ifnet *ifp = na->ifp;
	u_int ring_nr = kring->ring_id;
	u_int const head = kring->rhead;
	struct netmap_kring *peer_kring;

	/* device-specific */
	struct veth_priv *priv = netdev_priv(ifp);
	struct net_device *peer_ifp;
	struct netmap_adapter *peer_na;
	uint32_t oldhwcur = kring->nr_hwcur;

	rcu_read_lock();

	if (unlikely(!netif_carrier_ok(ifp)))
		goto out;

	peer_ifp = rcu_dereference(priv->peer);
	if (unlikely(!peer_ifp))
		goto out;

	peer_na = NA(peer_ifp);
	if (unlikely(!nm_netmap_on(peer_na)))
		goto out;

	mb();

	// 这里不发生真实内存交换，因为对端 peer veth 在调 txsync 时已经交换过了。
	// 这里就只要更新下游标即可。
	/*
	 * First part: import newly received packets.
	 * This is done by the peer's txsync.
	 */

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	kring->nr_hwcur = head;

	if (oldhwcur != head) {
		mb();  /* for writing kring->nr_hwcur */
		peer_kring = &peer_na->tx_rings[ring_nr];
		peer_kring->nm_notify(peer_kring, 0);
	}
out:
	rcu_read_unlock();

	return 0;
}


// 这一步发生在 veth 设备创建的时候（也是 veth patch 的主要内容）
// patched veth driver 会调用该函数将一个 veth attach 到 netmap
//
// 即在 netmap 内核模块中生成一个 veth_netmap_adapter 的过程，但这个 adapter 的真正使用需要等到 veth_netmap_reg 被调用。
//
static void
veth_netmap_attach(struct ifnet *ifp)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = ifp;
	na.pdev = NULL;
	na.num_tx_desc = 1024;
	na.num_rx_desc = 1024;
	na.nm_register = veth_netmap_reg;
	na.nm_txsync = veth_netmap_txsync;
	na.nm_rxsync = veth_netmap_rxsync;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
