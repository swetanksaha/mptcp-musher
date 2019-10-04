/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 100;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 0;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

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
        return mptcp_ratio_next_segment(meta_sk, reinject, subsk, limit);
}

static struct mptcp_sched_ops mptcp_sched_musher = {
	.get_subflow = musher_get_available_subflow,
	.next_segment = mptcp_musher_next_segment,
	.name = "musher",
	.owner = THIS_MODULE,
};

static int __init musher_register(void)
{
	if (mptcp_register_scheduler(&mptcp_sched_musher))
		return -1;

	return 0;
}

static void musher_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_musher);
}

module_init(musher_register);
module_exit(musher_unregister);

MODULE_AUTHOR("Swetank Kumar Saha, Shivang Aggarwal");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MuSher MPTCP");
MODULE_VERSION("0.01");
