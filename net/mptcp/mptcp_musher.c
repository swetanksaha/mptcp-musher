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

u16 regular_interval = 100;
u16 search_interval = 200;

struct mushersched_cb {
        u64 prev_txbytes;
        u64 prev_tstamp;
        u32 buffer_size;
        u8 buf_size_acc;
};

struct mushersched_priv {
        unsigned char reserved; /* DO NOT USE. Used by mptcp_ratio */
        struct mushersched_cb *musher_cb;
};

typedef enum {
        INIT_RIGHT,
        RIGHT_RATIO_SET,
        INIT_LEFT,
        LEFT_RATIO_SET,
        SEARCH_RATE
}search_state;

struct mushersched_meta_cb {
        unsigned int last_tstamp;
        u16 interval;
        u64 last_rate;
        u64 last_buf_size;
        long long rate_diff;
        long long buf_size_diff;
        u8 rate_cnt;
        u8 buf_size_cnt;
        bool in_search;
        u32 last_trigger_tstamp;
        u64 ref_rate;
        u64 ref_buf_size;
        u8 ref_cnt;
        search_state state;
        u64 cur_rate;
        u64 search_prev_rate;
        int step;
        u8 search_init_ratio;
};

struct mushersched_meta_priv {
        struct mushersched_meta_cb *musher_meta_cb;
};

static struct mushersched_priv *mushersched_get_priv(const struct tcp_sock *tp)
{
        return (struct mushersched_priv *)&tp->mptcp->mptcp_sched[0];
}

static struct mushersched_meta_priv *mushersched_get_meta_priv(const struct tcp_sock *tp)
{
	return (struct mushersched_meta_priv *)&tp->mpcb->mptcp_sched[0];
}

static u64 musher_get_rate(struct sock *meta_sk)
{
        const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
        struct sock *sk_it;
        struct dst_entry *dst;
        struct rtnl_link_stats64 stats;
        struct netdev_queue *txq;
        struct mushersched_cb *m_cb;
        char **devices;
        u64 rate = 0;
        u8 idx, found, cnt = 0;

        if (!mpcb->cnt_subflows) return rate; 
        devices = kcalloc(mpcb->cnt_subflows, IFNAMSIZ, GFP_KERNEL);

        mptcp_for_each_sk(mpcb, sk_it) {
                m_cb = mushersched_get_priv(tcp_sk(sk_it))->musher_cb;
                if (!m_cb) break;
                
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
                                    cnt++;
                                }
                        }

                }

        }
        
        kfree(devices);
        return rate;
}

static void musher_update_buffer_size(struct sock *meta_sk)
{
        const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
        struct sock *sk_it;
        struct tcp_sock *tp_it;
        struct mushersched_cb *m_cb;

        mptcp_for_each_sk(mpcb, sk_it) {
                tp_it = tcp_sk(sk_it);
                m_cb = mushersched_get_priv(tp_it)->musher_cb;
                if (m_cb) {
                        m_cb->buffer_size += (tp_it->write_seq - tp_it->snd_una);
                        m_cb->buf_size_acc++;
                }
        }
}

static u32 musher_get_buffer_size(struct sock *sk)
{
        struct mushersched_cb *m_cb = mushersched_get_priv(tcp_sk(sk))->musher_cb;
        u32 buf_size = 0;

        if (m_cb && m_cb->buf_size_acc) {
                buf_size = m_cb->buffer_size;
                do_div(buf_size, m_cb->buf_size_acc);

                m_cb->buffer_size = 0;
                m_cb->buf_size_acc = 0;
        }

        return buf_size;
}

/* We just look for any subflow that is available */
static struct sock *musher_get_available_subflow(struct sock *meta_sk,
					     struct sk_buff *skb,
					     bool zero_wnd_test)
{
        return ratio_get_available_subflow(meta_sk, skb, zero_wnd_test);
}


static void end_search(struct mushersched_meta_cb *m_meta_cb)
{
        m_meta_cb->in_search = false;
        m_meta_cb->interval = regular_interval;
}

static void find_optimal_ratio(struct mushersched_meta_cb *m_meta_cb, struct sock *meta_sk)
{
        printk("Search Triggered!");
        switch(m_meta_cb->state) {
               case INIT_RIGHT:
                        printk("INIT_RIGHT");
                        if (m_meta_cb->search_init_ratio + m_meta_cb->step <= 95) {
                                m_meta_cb->search_prev_rate = m_meta_cb->cur_rate;
                                sysctl_num_segments_flow_one = m_meta_cb->search_init_ratio + m_meta_cb->step;
                                m_meta_cb->state = RIGHT_RATIO_SET;
                        }
                        else m_meta_cb->state = INIT_LEFT;
                        break;
                
                case RIGHT_RATIO_SET:
                        printk("RIGHT_RATIO_SET");
                        if (m_meta_cb->cur_rate > m_meta_cb->search_prev_rate + 5000) {
                                sysctl_num_segments_flow_one += m_meta_cb->step;
                                m_meta_cb->search_prev_rate = m_meta_cb->cur_rate;
                                m_meta_cb->state = SEARCH_RATE;
                        }
                        else m_meta_cb->state = INIT_LEFT;
                        break;

                case INIT_LEFT:
                        printk("INIT_LEFT");
                        if (m_meta_cb->search_init_ratio - m_meta_cb->step >= 5) {
                                m_meta_cb->search_prev_rate = m_meta_cb->cur_rate;
                                sysctl_num_segments_flow_one = m_meta_cb->search_init_ratio - m_meta_cb->step;
                                m_meta_cb->state = LEFT_RATIO_SET;
                        }
                        else end_search(m_meta_cb);
                        break;

                case LEFT_RATIO_SET:
                        printk("LEFT_RATIO_SET");
                        if (m_meta_cb->cur_rate > m_meta_cb->search_prev_rate + 5000) {
                                m_meta_cb->step = -5;
                                sysctl_num_segments_flow_one += m_meta_cb->step;
                                m_meta_cb->search_prev_rate = m_meta_cb->cur_rate;
                                m_meta_cb->state = SEARCH_RATE;
                        }
                        else {
                                sysctl_num_segments_flow_one -= m_meta_cb->step;
                                end_search(m_meta_cb);
                        }
                        break;

                case SEARCH_RATE:
                        printk("SEARCH_RATE");
                        if (m_meta_cb->cur_rate < m_meta_cb->search_prev_rate) {
                                sysctl_num_segments_flow_one -= m_meta_cb->step;
                                end_search(m_meta_cb);
                        }
                        else {
                                m_meta_cb->search_prev_rate = m_meta_cb->cur_rate;
                                sysctl_num_segments_flow_one += m_meta_cb->step;
                        }
                        break;

        }
}

static bool trigger_search(struct mushersched_meta_cb *m_meta_cb)
{
        m_meta_cb->rate_cnt = m_meta_cb->buf_size_cnt = m_meta_cb->last_rate = m_meta_cb->last_buf_size = m_meta_cb->buf_size_diff = m_meta_cb->ref_cnt = 0;
        
        if (jiffies_to_msecs(jiffies - m_meta_cb->last_trigger_tstamp) >= 3000) {
                m_meta_cb->in_search = true;
                m_meta_cb->interval = search_interval;
                m_meta_cb->step = 5;
                m_meta_cb->last_trigger_tstamp = jiffies;
                m_meta_cb->state = INIT_RIGHT;
                m_meta_cb->search_init_ratio = sysctl_num_segments_flow_one;
        }

        return m_meta_cb->in_search;
}

static struct sk_buff *mptcp_musher_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
        const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;        
        struct mushersched_meta_cb *m_meta_cb = mushersched_get_meta_priv(tcp_sk(meta_sk))->musher_meta_cb;
        struct sock *sk_it;
        
        u64 cur_rate = 0, cur_buf_size = 0;
       
        musher_update_buffer_size(meta_sk);
         
        if (jiffies_to_msecs(jiffies - m_meta_cb->last_tstamp) > m_meta_cb->interval) {
                cur_rate = musher_get_rate(meta_sk);
                m_meta_cb->cur_rate = cur_rate;

                printk("cur_rate: %lld, last_rate: %lld, cur_ratio: %u, rate_diff: %lld, %d", cur_rate, m_meta_cb->last_rate, sysctl_num_segments_flow_one, m_meta_cb->rate_diff, m_meta_cb->in_search);
                mptcp_for_each_sk(mpcb, sk_it) {
                        cur_buf_size += musher_get_buffer_size(sk_it); 
                }

                if (!m_meta_cb->in_search && !m_meta_cb->last_rate) {
                        if (m_meta_cb->ref_cnt == 5) {
                                do_div(m_meta_cb->ref_rate, 5);
                                m_meta_cb->last_rate = m_meta_cb->ref_rate;
                                printk("ref_rate: %llu", m_meta_cb->ref_rate);

                                do_div(m_meta_cb->ref_buf_size, 5);
                                m_meta_cb->last_buf_size = m_meta_cb->ref_buf_size;

                                m_meta_cb->ref_rate = m_meta_cb->ref_buf_size = m_meta_cb->ref_cnt = m_meta_cb->rate_diff = 0;
                        }
                        else {
                                m_meta_cb->ref_rate += cur_rate;
                                m_meta_cb->ref_buf_size += cur_buf_size;
                                m_meta_cb->ref_cnt += 1;
                        }

                        goto exit;
                }

                m_meta_cb->rate_diff += cur_rate - m_meta_cb->last_rate;
                m_meta_cb->buf_size_diff += cur_buf_size - m_meta_cb->last_buf_size;
 
                if (!m_meta_cb->in_search) {
                        /* Trigger if rate_diff threshold exceeded */
                        printk("abs: %lld", abs(m_meta_cb->rate_diff));
                        if (abs(m_meta_cb->rate_diff) > 200000) {
                                m_meta_cb->buf_size_cnt = 0;
                                m_meta_cb->rate_cnt += 1;
            
                                if (m_meta_cb->rate_cnt == 5){
                                        printk("Potential rate trigger!");
                                        trigger_search(m_meta_cb);
                                        goto exit;
                                }
                        }

                        /* Trigger if buf_size_diff threshold exceeded */
                        else if (m_meta_cb->buf_size_diff < -75000) {
                                m_meta_cb->rate_cnt = 0;
                                m_meta_cb->buf_size_cnt += 1;

                                if (m_meta_cb->buf_size_cnt == 5) {
                                        printk("Potential buffer trigger!");
                                        trigger_search(m_meta_cb);
                                        goto exit;
                                }
                        }

                        else {
                                m_meta_cb->buf_size_cnt = 0;
                                m_meta_cb->rate_cnt = 0;
                        }

                        m_meta_cb->last_rate = cur_rate;
                        m_meta_cb->last_buf_size = cur_buf_size;
                }
                /* Searching for a new ratio */
                else find_optimal_ratio(m_meta_cb, meta_sk);
exit:
                m_meta_cb->last_tstamp = jiffies;
        }

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
        struct mushersched_meta_cb *m_meta_cb = NULL;        

        if (mptcp(tp) && !strcmp(tp->mpcb->sched_ops->name, mptcp_sched_musher.name)) {
                switch(state) {
                case TCP_ESTABLISHED:
                        if (oldstate != TCP_ESTABLISHED) {
                                if (is_meta_tp(tp)) {
                                        m_meta_cb = (struct mushersched_meta_cb *) kcalloc(1, sizeof(struct mushersched_meta_cb), GFP_KERNEL);
                                        m_meta_cb->interval = regular_interval;
                                        if (m_meta_cb) mushersched_get_meta_priv(tp)->musher_meta_cb = m_meta_cb;
                                }
                                else {
                                        m_cb = (struct mushersched_cb *) kcalloc(1, sizeof(struct mushersched_cb), GFP_KERNEL);
                                        if (m_cb) mushersched_get_priv(tp)->musher_cb = m_cb;
                                }
                        }
                        break;

                case TCP_TIME_WAIT:
                case TCP_CLOSE:
                        if (is_meta_tp(tp)) {
                                m_meta_cb = mushersched_get_meta_priv(tp)->musher_meta_cb;
                                if (m_meta_cb) {
                                        kfree(m_meta_cb);
                                        mushersched_get_meta_priv(tp)->musher_meta_cb = NULL;
                                }
                        }
                        else {
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
