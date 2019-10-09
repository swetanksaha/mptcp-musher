/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 100;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 0;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

struct mushersched_cb {
        u64 prev_txbytes;
        u64 prev_tstamp;
};

struct mushersched_priv {
        unsigned char reserved; /* DO NOT USE. Used by mptcp_ratio */
        struct mushersched_cb *musher_cb;
};

static struct mushersched_priv *mushersched_get_priv(const struct tcp_sock *tp)
{
        return (struct mushersched_priv *)&tp->mptcp->mptcp_sched[0];
}

static u64 get_mptcp_rate(struct sock *meta_sk)
{
        const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
        struct sock *sk_it;
        struct dst_entry *dst;
        struct rtnl_link_stats64 stats;
        struct netdev_queue *txq;
        struct mushersched_cb *m_cb;
        u64 rate = 0;

        char **devices = kcalloc(mpcb->cnt_subflows, IFNAMSIZ, GFP_KERNEL);
        u8 idx, found, cnt = 0;

        if (!devices) return rate;

        mptcp_for_each_sk(mpcb, sk_it) {
                m_cb = mushersched_get_priv(tcp_sk(sk_it))->musher_cb;       
                dst = sk_dst_get(sk_it);

                if (dst && dst->dev) {
                        dev_get_stats(dst->dev, &stats);
                        txq = netdev_get_tx_queue(dst->dev, 0);

                        if (txq) {
                                if (!m_cb->prev_txbytes) m_cb->prev_txbytes = stats.tx_bytes;
                                if (!m_cb->prev_tstamp) m_cb->prev_tstamp = txq->trans_start;

                                if (m_cb->prev_txbytes && m_cb->prev_tstamp && txq->trans_start != m_cb->prev_tstamp
                                        && jiffies_to_msecs(txq->trans_start - m_cb->prev_tstamp)) {
                                    
                                        found = 0;
                                        for(idx = 0; idx < cnt; idx++) {
                                                if (!strcmp(devices[idx], dst->dev->name)) {
                                                        found = 1;
                                                        break;
                                                }
                                        }
                                        if (!found)
                                                rate += ((stats.tx_bytes - m_cb->prev_txbytes)*8)/(jiffies_to_msecs(txq->trans_start - m_cb->prev_tstamp));
                                    
                                    m_cb->prev_txbytes = stats.tx_bytes;
                                    m_cb->prev_tstamp = txq->trans_start;
                                    devices[cnt] = dst->dev->name;
                                    cnt += 1;
                                }
                        }

                }

        }
        
        kfree(devices);
        return rate;
}

/* We just look for any subflow that is available */
static struct sock *musher_get_available_subflow(struct sock *meta_sk,
					     struct sk_buff *skb,
					     bool zero_wnd_test)
{
        return ratio_get_available_subflow(meta_sk, skb, zero_wnd_test);
}

static struct sk_buff *mptcp_musher_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
        get_mptcp_rate(meta_sk);        
        return mptcp_ratio_next_segment(meta_sk, reinject, subsk, limit);
}

static struct mptcp_sched_ops mptcp_sched_musher = {
	.get_subflow = musher_get_available_subflow,
	.next_segment = mptcp_musher_next_segment,
	.name = "musher",
	.owner = THIS_MODULE,
};

static void jtcp_set_state(struct sock *sk, int state)
{
        int oldstate = sk->sk_state;
        const struct tcp_sock *tp = tcp_sk(sk);
        struct mushersched_cb *m_cb = NULL;
        
        if (mptcp(tp) && !strcmp(tp->mpcb->sched_ops->name, mptcp_sched_musher.name)) {
                switch(state) {
                case TCP_ESTABLISHED:
                        if (oldstate != TCP_ESTABLISHED && !is_meta_tp(tp)) {
                                m_cb = (struct mushersched_cb *) kcalloc(1, sizeof(struct mushersched_cb), GFP_KERNEL);
                                if (m_cb) mushersched_get_priv(tp)->musher_cb = m_cb;
                        }
                        break;

                case TCP_TIME_WAIT:
                case TCP_CLOSE:
                        if (!is_meta_tp(tp)) {
                                m_cb = mushersched_get_priv(tp)->musher_cb;
                                if (m_cb) {
                                        kfree(m_cb);
                                        mushersched_get_priv(tp)->musher_cb = NULL;
                                }
                        }
                        break;
                }
        }
        jprobe_return();
}

static struct jprobe musher_jprobe = {
        .kp = {
                .symbol_name    = "tcp_set_state",
        },
        .entry  = jtcp_set_state,
};

static int __init musher_register(void)
{
        BUILD_BUG_ON(__same_type(tcp_set_state,
                                 jtcp_set_state) == 0);

	if (mptcp_register_scheduler(&mptcp_sched_musher))
		return -1;

        if (register_jprobe(&musher_jprobe))
                return -2;

	return 0;
}

static void musher_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_musher);
        unregister_jprobe(&musher_jprobe);
}

module_init(musher_register);
module_exit(musher_unregister);

MODULE_AUTHOR("Swetank Kumar Saha, Shivang Aggarwal");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MuSher MPTCP");
MODULE_VERSION("0.01");
