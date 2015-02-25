/*
 * Reference : <linux_kernel_sources>/net/sched/sch_fifo.c and <linux_kernel_sources>/net/sched/sch_cbq.c
 */

/*
 * DYCBQ - Dynamic Buffer Management in Class-Based Queuing (CBQ)
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

#define MAX_CHILD_CLASSES	2

struct dycbq_sched_data;
extern struct Qdisc_ops dypfifo_qdisc_ops;
extern int dypfifo_enqueue(struct sk_buff *, struct Qdisc *,struct dycbq_class * );
extern void incrementDequeue(struct dycbq_class *cl);

enum {
	TCA_DYCBQ_UNSPEC,
	TCA_DYCBQ_LSSOPT,
	TCA_DYCBQ_WRROPT,
	TCA_DYCBQ_FOPT,
	TCA_DYCBQ_OVL_STRATEGY,
	TCA_DYCBQ_RATE,
	TCA_DYCBQ_RTAB,
	TCA_DYCBQ_POLICE,
	__TCA_DYCBQ_MAX,
};

#define TCA_DYCBQ_MAX	(__TCA_DYCBQ_MAX - 1)

struct tc_dycbq_lssopt {
	unsigned char	change;
	unsigned char	flags;
#define TCF_DYCBQ_LSS_BOUNDED	1
#define TCF_CBQ_LSS_ISOLATED	2
	unsigned char  	ewma_log;
	unsigned char  	level;
#define TCF_CBQ_LSS_FLAGS	1
#define TCF_CBQ_LSS_EWMA	2
#define TCF_CBQ_LSS_MAXIDLE	4
#define TCF_CBQ_LSS_MINIDLE	8
#define TCF_CBQ_LSS_OFFTIME	0x10
#define TCF_CBQ_LSS_AVPKT	0x20
	__u32		maxidle;
	__u32		minidle;
	__u32		offtime;
	__u32		avpkt;
	__u32 		limit;		//No.of.Packets
	__u32		variableSpace; //No.Of.packets
	__u32 		totalSharedSpace; //No.Of.packets
};


/*
 * DY_CBQ Struct : This struct contains variables that are required for WRR dequeuing, to access children in hierarchy that are similar to struct cbq_class
 * This struct has extra parameters that limit the pfifo queue, variable space that is attached to this class.
 * Also, stats like datasent, dataenqueued(datareceived), dataDropped from the time class was created in bytes.
 *
 */
struct dycbq_class {
	struct Qdisc_class_common common;
	struct dycbq_class	*next_alive;
/*dycbq scheduling algorithm maintains a list of active traffic classes for
scheduling the class based on the priority. This ﬁeld will point to the next
class with backlog of packets from the list of active classes */

/* Parameters */
	unsigned char		priority;	/*   This ﬁeld contains the class priority which is used in scheduling a dycbq class.   */
	unsigned char		priority2;	/*  This  ﬁeld contains the class priority to be used after the overlimit. A dycbq class is of three types:
	overlimit, underlimit, and at limit. Depending on the usage of the class in dycbq scheduling function, a class is classed overlimit,
	underlimit, and at limit based on the allocated bandwidth. */

	unsigned char		ewma_log;	/*   This field is used for calculating the idle time calculation required in dycbq scheduling function.   */
	unsigned char		ovl_strategy;
#ifdef CONFIG_NET_CLS_ACT
	unsigned char		police;
#endif

	u32				defmap;

	/* Link-sharing scheduler parameters */
	long			maxidle;	/* Class parameters: see below. */
	long			offtime;
	long			minidle;
	u32				avpkt;
	struct qdisc_rate_table	*R_tab;
	/* Overlimit strategy parameters */
	void			(*overlimit)(struct dycbq_class *cl);
	psched_tdiff_t		penalty;
	/* General scheduler (WRR) parameters */
	long			allot;
	/*
	 allot Specifies how many bytes a qdisc can dequeue during each round. This is reconfigurable and depends on the weight field of the dycbq_class struct
	*/
	long			quantum;
	/*
		Specifies the allotment per weighted round robin based on the bandwidth assigned for the class
	 */
	long			weight;
	/*
	   If the dycbq_class has more bandwidth than other classes in the queue, then the weight ﬁeld is used for the high-bandwidth class to send more data
		in one round than the others.
	 */

	struct Qdisc		*qdisc;		/* Ptr to DYCBQ discipline */
	struct dycbq_class	*split;		/* Ptr to split node */
	struct dycbq_class	*share;		/* Ptr to LS parent in the class tree */
	struct dycbq_class	*tparent;	/* Ptr to tree parent in the class tree */
	struct dycbq_class	*borrow;	/* NULL if class is bandwidth limited;
						   parent otherwise */
	struct dycbq_class	*sibling;	/* child classes at same level */
	struct dycbq_class	*children;	/* Pointer to children chain */

	struct Qdisc		*q;		/* Elementary queueing discipline, which is for DYCBQ is always DYFIFO */

/* Variables */
	unsigned char		cpriority;	/* Effective priority */
	unsigned char		delayed;
	unsigned char		level;		/* level of the class in hierarchy:
						   0 for leaf classes, and maximal
						   level of children + 1 for nodes.
						 */
	psched_time_t		last;		/* Last end of service */
	psched_time_t		undertime;
	long			avgidle;
	long			deficit;	/* Saved deficit for WRR */
	psched_time_t		penalized;
	struct gnet_stats_basic_packed bstats;
	struct gnet_stats_queue qstats;
	struct gnet_stats_rate_est64 rate_est;
	struct tc_cbq_xstats	xstats;
	struct tcf_proto	*filter_list;

	int			refcnt;
	int			filters;
	u32			variableSpace;							//This variable indicates part of total shared space allocated to this class
	u32 		limit;									//This specifies the maximum number of packets that can be stored in dedicated space
	u32			totalSharedSpace;						//This is totalSharedSpace of root queuing discipline i.,e dycbq. Gets value from parent while linking class
	int 		classesAdded;							//Total classes that are added to this queuing discipline
	int 		packetsReceived;						//Total packets that are received by this class i.,e these may have been enqueued/dropped.
	int 		packetsEnqueued;						//Total packets that are enqueued by this class
	int			packetsDequeued;						//Total packets that are dequeued from this class
	int  		packetsInVariableSpace;					//Total packets that are in variable space
	int			packetsDropped;							//Total packets that are dropped by this class
	unsigned long long int datasent;					//Total data that was sent i.e., dequeued (bytes)
	unsigned long long int datareceived;				//Total data that was received i.e., here it is data enqueued (in bytes)
	unsigned long long int dataDropped;					//Total data that was dropped (in bytes)
	struct dycbq_class	*defaults[TC_PRIO_MAX + 1];
};

/*
 * This struct is similar to cbq_sched_data.
 */
struct dycbq_sched_data {
	struct Qdisc_class_hash	clhash;			/* Hash table of all classes */
	int			nclasses[TC_CBQ_MAXPRIO + 1];
	unsigned int		quanta[TC_CBQ_MAXPRIO + 1];

	struct dycbq_class	link;

	unsigned int		activemask;
	struct dycbq_class	*active[TC_CBQ_MAXPRIO + 1];	/* List of all classes
								   with backlog */

#ifdef CONFIG_NET_CLS_ACT
	struct dycbq_class	*rx_class;
#endif
	struct dycbq_class	*tx_class;
	struct dycbq_class	*tx_borrowed;
	int			tx_len;
	psched_time_t		now;		/* Cached timestamp */
	psched_time_t		now_rt;		/* Cached real time */
	unsigned int		pmask;

	struct hrtimer		delay_timer;
	struct qdisc_watchdog	watchdog;	/* Watchdog timer,
						   started when DYCBQ has
						   backlog, but cannot
						   transmit just now */
	psched_tdiff_t		wd_expires;
	int			toplevel;
	u32			hgenerator;
};


#define L2T(cl, len)	qdisc_l2t((cl)->R_tab, len)
/*
 * Updates the packet length and puts it in control buffer of sk_buff i.,e incoming packet
 */
static inline void qdisc_calculate_pkt_len1(struct sk_buff *skb,
					   const struct Qdisc *sch)
{
#ifdef CONFIG_NET_SCHED
	struct qdisc_size_table *stab = rcu_dereference_bh(sch->stab);

	if (stab)
		__qdisc_calculate_pkt_len(skb, stab);
#endif
}
/*
 * This is called while enqueueing packet in FIFO queue (with shared space) attached to class
 */
static inline int qdisc_enqueue1(struct sk_buff *skb, struct Qdisc *sch,struct dycbq_class *cl)
{
	qdisc_calculate_pkt_len1(skb, sch);
	return dypfifo_enqueue(skb, sch, cl);
}

/*
 * This function is called to get dycbq_class struct stored in hashtable based on classid
 */
static inline struct dycbq_class *
dycbq_class_lookup(struct dycbq_sched_data *q, u32 classid)
{
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, classid);
	if (clc == NULL)
		return NULL;
	return container_of(clc, struct dycbq_class, common);
}

#ifdef CONFIG_NET_CLS_ACT

static struct dycbq_class *
dycbq_reclassify(struct sk_buff *skb, struct dycbq_class *this)
{
	struct dycbq_class *cl;

	for (cl = this->tparent; cl; cl = cl->tparent) {
		struct dycbq_class *new = cl->defaults[TC_PRIO_BESTEFFORT];

		if (new != NULL && new != this)
			return new;
	}
	return NULL;
}

#endif

/* Classify packet. The procedure is pretty complicated, but
 * it allows us to combine link sharing and priority scheduling
 * transparently.
 *
 * Namely, you can put link sharing rules (f.e. route based) at root of DYCBQ,
 * so that it resolves to split nodes. Then packets are classified
 * by logical priority, or a more specific classifier may be attached
 * to the split node.
 */

static struct dycbq_class *
dycbq_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *head = &q->link;
	struct dycbq_class **defmap;
	struct dycbq_class *cl = NULL;
	u32 prio = skb->priority;
	struct tcf_result res;

	/*
	 *  Step 1. If skb->priority points to one of our classes, use it.
	 */
	if (TC_H_MAJ(prio ^ sch->handle) == 0 &&
	    (cl = dycbq_class_lookup(q, prio)) != NULL)
		return cl;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	for (;;) {
		int result = 0;
		defmap = head->defaults;

		/*
		 * Step 2+n. Apply classifier.
		 */
		if (!head->filter_list ||
		    (result = tc_classify_compat(skb, head->filter_list, &res)) < 0)
			goto fallback;

		cl = (void *)res.class;
		if (!cl) {
			if (TC_H_MAJ(res.classid))
				cl = dycbq_class_lookup(q, res.classid);
			else if ((cl = defmap[res.classid & TC_PRIO_MAX]) == NULL)
				cl = defmap[TC_PRIO_BESTEFFORT];

			if (cl == NULL)
				goto fallback;
		}
		if (cl->level >= head->level)
			goto fallback;
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
		case TC_ACT_SHOT:
			return NULL;
		case TC_ACT_RECLASSIFY:
			return dycbq_reclassify(skb, cl);
		}
#endif
		if (cl->level == 0)
			return cl;

		/*
		 * Step 3+n. If classifier selected a link sharing class,
		 *	   apply agency specific classifier.
		 *	   Repeat this procdure until we hit a leaf node.
		 */
		head = cl;
	}

fallback:
	cl = head;

	/*
	 * Step 4. No success...
	 */
	if (TC_H_MAJ(prio) == 0 &&
	    !(cl = head->defaults[prio & TC_PRIO_MAX]) &&
	    !(cl = head->defaults[TC_PRIO_BESTEFFORT]))
		return head;

	return cl;
}

/*
 * A packet has just been enqueued on the empty class.
 * dycbq_activate_class adds it to the tail of active class list
 * of its priority band.
 */

static inline void dycbq_activate_class(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);
	int prio = cl->cpriority;
	struct dycbq_class *cl_tail;

	cl_tail = q->active[prio];
	q->active[prio] = cl;

	if (cl_tail != NULL) {
		cl->next_alive = cl_tail->next_alive;
		cl_tail->next_alive = cl;
	} else {
		cl->next_alive = cl;
		q->activemask |= (1<<prio);
	}
}

/*
 * Unlink class from active chain.
 * Note that this same procedure is done directly in dycbq_dequeue*
 * during round-robin procedure.
 */

static void dycbq_deactivate_class(struct dycbq_class *this)
{
	struct dycbq_sched_data *q = qdisc_priv(this->qdisc);
	int prio = this->cpriority;
	struct dycbq_class *cl;
	struct dycbq_class *cl_prev = q->active[prio];

	do {
		cl = cl_prev->next_alive;
		if (cl == this) {
			cl_prev->next_alive = cl->next_alive;
			cl->next_alive = NULL;

			if (cl == q->active[prio]) {
				q->active[prio] = cl_prev;
				if (cl == q->active[prio]) {
					q->active[prio] = NULL;
					q->activemask &= ~(1<<prio);
					return;
				}
			}
			return;
		}
	} while ((cl_prev = cl) != q->active[prio]);
}

static void
dycbq_mark_toplevel(struct dycbq_sched_data *q, struct dycbq_class *cl)
{
	int toplevel = q->toplevel;

	if (toplevel > cl->level && !(qdisc_is_throttled(cl->q))) {
		psched_time_t now;
		psched_tdiff_t incr;

		now = psched_get_time();
		incr = now - q->now_rt;
		now = q->now + incr;

		do {
			if (cl->undertime < now) {
				q->toplevel = cl->level;
				return;
			}
		} while ((cl = cl->borrow) != NULL && toplevel > cl->level);
	}
}


static int
dycbq_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	int uninitialized_var(ret);
	struct dycbq_class *cl = dycbq_classify(skb, sch, &ret);

#ifdef CONFIG_NET_CLS_ACT
	q->rx_class = cl;
#endif

	if (cl == NULL) {
		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}


#ifdef CONFIG_NET_CLS_ACT
	cl->q->__parent = sch;
#endif

	cl->packetsReceived++;
	ret = qdisc_enqueue1(skb, cl->q,cl);
	if (ret == NET_XMIT_SUCCESS) {
		sch->q.qlen++;
		dycbq_mark_toplevel(q, cl);
		if (!cl->next_alive)
			dycbq_activate_class(cl);
		return ret;
	}

	if (net_xmit_drop_count(ret)) {
		sch->qstats.drops++;
		dycbq_mark_toplevel(q, cl);
		cl->qstats.drops++;
	}
	return ret;
}

/* Overlimit actions */

/* TC_CBQ_OVL_CLASSIC: (default) penalize leaf class by adding offtime */

static void dycbq_ovl_classic(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);
	psched_tdiff_t delay = cl->undertime - q->now;

	if (!cl->delayed) {
		delay += cl->offtime;

		if (cl->avgidle < 0)
			delay -= (-cl->avgidle) - ((-cl->avgidle) >> cl->ewma_log);
		if (cl->avgidle < cl->minidle)
			cl->avgidle = cl->minidle;
		if (delay <= 0)
			delay = 1;
		cl->undertime = q->now + delay;

		cl->xstats.overactions++;
		cl->delayed = 1;
	}
	if (q->wd_expires == 0 || q->wd_expires > delay)
		q->wd_expires = delay;

	/* Dirty work! We must schedule wakeups based on
	 * real available rate, rather than leaf rate,
	 * which may be tiny (even zero).
	 */
	if (q->toplevel == TC_CBQ_MAXLEVEL) {
		struct dycbq_class *b;
		psched_tdiff_t base_delay = q->wd_expires;

		for (b = cl->borrow; b; b = b->borrow) {
			delay = b->undertime - q->now;
			if (delay < base_delay) {
				if (delay <= 0)
					delay = 1;
				base_delay = delay;
			}
		}

		q->wd_expires = base_delay;
	}
}

/* TC_CBQ_OVL_RCLASSIC: penalize by offtime classes in hierarchy, when
 * they go overlimit
 */

static void dycbq_ovl_rclassic(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);
	struct dycbq_class *this = cl;

	do {
		if (cl->level > q->toplevel) {
			cl = NULL;
			break;
		}
	} while ((cl = cl->borrow) != NULL);

	if (cl == NULL)
		cl = this;
	dycbq_ovl_classic(cl);
}

/* TC_CBQ_OVL_DELAY: delay until it will go to underlimit */

static void dycbq_ovl_delay(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);
	psched_tdiff_t delay = cl->undertime - q->now;

	if (test_bit(__QDISC_STATE_DEACTIVATED,
		     &qdisc_root_sleeping(cl->qdisc)->state))
		return;

	if (!cl->delayed) {
		psched_time_t sched = q->now;
		ktime_t expires;

		delay += cl->offtime;
		if (cl->avgidle < 0)
			delay -= (-cl->avgidle) - ((-cl->avgidle) >> cl->ewma_log);
		if (cl->avgidle < cl->minidle)
			cl->avgidle = cl->minidle;
		cl->undertime = q->now + delay;

		if (delay > 0) {
			sched += delay + cl->penalty;
			cl->penalized = sched;
			cl->cpriority = TC_CBQ_MAXPRIO;
			q->pmask |= (1<<TC_CBQ_MAXPRIO);

			expires = ns_to_ktime(PSCHED_TICKS2NS(sched));
			if (hrtimer_try_to_cancel(&q->delay_timer) &&
			    ktime_to_ns(ktime_sub(
					hrtimer_get_expires(&q->delay_timer),
					expires)) > 0)
				hrtimer_set_expires(&q->delay_timer, expires);
			hrtimer_restart(&q->delay_timer);
			cl->delayed = 1;
			cl->xstats.overactions++;
			return;
		}
		delay = 1;
	}
	if (q->wd_expires == 0 || q->wd_expires > delay)
		q->wd_expires = delay;
}

/* TC_CBQ_OVL_LOWPRIO: penalize class by lowering its priority band */

static void dycbq_ovl_lowprio(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);

	cl->penalized = q->now + cl->penalty;

	if (cl->cpriority != cl->priority2) {
		cl->cpriority = cl->priority2;
		q->pmask |= (1<<cl->cpriority);
		cl->xstats.overactions++;
	}
	dycbq_ovl_classic(cl);
}

/* TC_CBQ_OVL_DROP: penalize class by dropping */

static void dycbq_ovl_drop(struct dycbq_class *cl)
{
	if (cl->q->ops->drop)
		if (cl->q->ops->drop(cl->q))
			cl->qdisc->q.qlen--;
	cl->xstats.overactions++;
	dycbq_ovl_classic(cl);
}

static psched_tdiff_t dycbq_undelay_prio(struct dycbq_sched_data *q, int prio,
				       psched_time_t now)
{
	struct dycbq_class *cl;
	struct dycbq_class *cl_prev = q->active[prio];
	psched_time_t sched = now;

	if (cl_prev == NULL)
		return 0;

	do {
		cl = cl_prev->next_alive;
		if (now - cl->penalized > 0) {
			cl_prev->next_alive = cl->next_alive;
			cl->next_alive = NULL;
			cl->cpriority = cl->priority;
			cl->delayed = 0;
			dycbq_activate_class(cl);

			if (cl == q->active[prio]) {
				q->active[prio] = cl_prev;
				if (cl == q->active[prio]) {
					q->active[prio] = NULL;
					return 0;
				}
			}

			cl = cl_prev->next_alive;
		} else if (sched - cl->penalized > 0)
			sched = cl->penalized;
	} while ((cl_prev = cl) != q->active[prio]);

	return sched - now;
}

static enum hrtimer_restart dycbq_undelay(struct hrtimer *timer)
{
	struct dycbq_sched_data *q = container_of(timer, struct dycbq_sched_data,
						delay_timer);
	struct Qdisc *sch = q->watchdog.qdisc;
	psched_time_t now;
	psched_tdiff_t delay = 0;
	unsigned int pmask;

	now = psched_get_time();

	pmask = q->pmask;
	q->pmask = 0;

	while (pmask) {
		int prio = ffz(~pmask);
		psched_tdiff_t tmp;

		pmask &= ~(1<<prio);

		tmp = dycbq_undelay_prio(q, prio, now);
		if (tmp > 0) {
			q->pmask |= 1<<prio;
			if (tmp < delay || delay == 0)
				delay = tmp;
		}
	}

	if (delay) {
		ktime_t time;

		time = ktime_set(0, 0);
		time = ktime_add_ns(time, PSCHED_TICKS2NS(now + delay));
		hrtimer_start(&q->delay_timer, time, HRTIMER_MODE_ABS);
	}

	qdisc_unthrottled(sch);
	__netif_schedule(qdisc_root(sch));
	return HRTIMER_NORESTART;
}

#ifdef CONFIG_NET_CLS_ACT
static int dycbq_reshape_fail(struct sk_buff *skb, struct Qdisc *child)
{
	struct Qdisc *sch = child->__parent;
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl = q->rx_class;

	q->rx_class = NULL;

	if (cl && (cl = dycbq_reclassify(skb, cl)) != NULL) {
		int ret;

		dycbq_mark_toplevel(q, cl);

		q->rx_class = cl;
		cl->q->__parent = sch;

		ret = qdisc_enqueue(skb, cl->q);
		if (ret == NET_XMIT_SUCCESS) {
			sch->q.qlen++;
			if (!cl->next_alive)
				dycbq_activate_class(cl);
			return 0;
		}
		if (net_xmit_drop_count(ret))
			sch->qstats.drops++;
		return 0;
	}

	sch->qstats.drops++;
	return -1;
}
#endif

/*
 * It is mission critical procedure.
 *
 * We "regenerate" toplevel cutoff, if transmitting class
 * has backlog and it is not regulated. It is not part of
 * original CBQ description, but looks more reasonable.
 * Probably, it is wrong. This question needs further investigation.
 */

static inline void
dycbq_update_toplevel(struct dycbq_sched_data *q, struct dycbq_class *cl,
		    struct dycbq_class *borrowed)
{
	if (cl && q->toplevel >= borrowed->level) {
		if (cl->q->q.qlen > 1) {
			do {
				if (borrowed->undertime == PSCHED_PASTPERFECT) {
					q->toplevel = borrowed->level;
					return;
				}
			} while ((borrowed = borrowed->borrow) != NULL);
		}
#if 0
		q->toplevel = TC_CBQ_MAXLEVEL;
#endif
	}
}

static void
dycbq_update(struct dycbq_sched_data *q)
{
	struct dycbq_class *this = q->tx_class;
	struct dycbq_class *cl = this;
	int len = q->tx_len;

	q->tx_class = NULL;

	for ( ; cl; cl = cl->share) {
		long avgidle = cl->avgidle;
		long idle;

		cl->bstats.packets++;
		cl->bstats.bytes += len;

		/*
		 * (now - last) is total time between packet right edges.
		 * (last_pktlen/rate) is "virtual" busy time, so that
		 *
		 *	idle = (now - last) - last_pktlen/rate
		 */

		idle = q->now - cl->last;
		if ((unsigned long)idle > 128*1024*1024) {
			avgidle = cl->maxidle;
		} else {
			idle -= L2T(cl, len);

		/* true_avgidle := (1-W)*true_avgidle + W*idle,
		 * where W=2^{-ewma_log}. But cl->avgidle is scaled:
		 * cl->avgidle == true_avgidle/W,
		 * hence:
		 */
			avgidle += idle - (avgidle>>cl->ewma_log);
		}

		if (avgidle <= 0) {
			/* Overlimit or at-limit */

			if (avgidle < cl->minidle)
				avgidle = cl->minidle;

			cl->avgidle = avgidle;

			/* Calculate expected time, when this class
			 * will be allowed to send.
			 * It will occur, when:
			 * (1-W)*true_avgidle + W*delay = 0, i.e.
			 * idle = (1/W - 1)*(-true_avgidle)
			 * or
			 * idle = (1 - W)*(-cl->avgidle);
			 */
			idle = (-avgidle) - ((-avgidle) >> cl->ewma_log);


			idle -= L2T(&q->link, len);
			idle += L2T(cl, len);

			cl->undertime = q->now + idle;
		} else {
			/* Underlimit */

			cl->undertime = PSCHED_PASTPERFECT;
			if (avgidle > cl->maxidle)
				cl->avgidle = cl->maxidle;
			else
				cl->avgidle = avgidle;
		}
		cl->last = q->now;
	}

	dycbq_update_toplevel(q, this, q->tx_borrowed);
}

static inline struct dycbq_class *
dycbq_under_limit(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);
	struct dycbq_class *this_cl = cl;

	if (cl->tparent == NULL)
		return cl;

	if (cl->undertime == PSCHED_PASTPERFECT || q->now >= cl->undertime) {
		cl->delayed = 0;
		return cl;
	}

	do {

		cl = cl->borrow;
		if (!cl) {
			this_cl->qstats.overlimits++;
			this_cl->overlimit(this_cl);
			return NULL;
		}
		if (cl->level > q->toplevel)
			return NULL;
	} while (cl->undertime != PSCHED_PASTPERFECT && q->now < cl->undertime);

	cl->delayed = 0;
	return cl;
}

static inline struct sk_buff *
dycbq_dequeue_prio(struct Qdisc *sch, int prio)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl_tail, *cl_prev, *cl;
	struct sk_buff *skb;
	int deficit;

	cl_tail = cl_prev = q->active[prio];
	cl = cl_prev->next_alive;

	do {
		deficit = 0;
		do {
			struct dycbq_class *borrow = cl;

			if (cl->q->q.qlen &&
			    (borrow = dycbq_under_limit(cl)) == NULL)
				goto skip_class;

			if (cl->deficit <= 0) {
				deficit = 1;
				cl->deficit += cl->quantum;
				goto next_class;
			}

			skb = cl->q->dequeue(cl->q);

			if (skb == NULL)
				goto skip_class;
			incrementDequeue(cl);
			cl->datasent = cl->datasent + skb->len;

			cl->deficit -= qdisc_pkt_len(skb);
			q->tx_class = cl;
			q->tx_borrowed = borrow;
			if (borrow != cl) {
#ifndef CBQ_XSTATS_BORROWS_BYTES
				borrow->xstats.borrows++;
				cl->xstats.borrows++;
#else
				borrow->xstats.borrows += qdisc_pkt_len(skb);
				cl->xstats.borrows += qdisc_pkt_len(skb);
#endif
			}
			q->tx_len = qdisc_pkt_len(skb);

			if (cl->deficit <= 0) {
				q->active[prio] = cl;
				cl = cl->next_alive;
				cl->deficit += cl->quantum;
			}
			return skb;

skip_class:
			if (cl->q->q.qlen == 0 || prio != cl->cpriority) {

				cl_prev->next_alive = cl->next_alive;
				cl->next_alive = NULL;

				if (cl == cl_tail) {
					/* Repair it! */
					cl_tail = cl_prev;

					if (cl == cl_tail) {
						q->active[prio] = NULL;
						q->activemask &= ~(1<<prio);
						if (cl->q->q.qlen)
							dycbq_activate_class(cl);
						return NULL;
					}

					q->active[prio] = cl_tail;
				}
				if (cl->q->q.qlen)
					dycbq_activate_class(cl);

				cl = cl_prev;
			}

next_class:
			cl_prev = cl;
			cl = cl->next_alive;
		} while (cl_prev != cl_tail);
	} while (deficit);

	q->active[prio] = cl_prev;

	return NULL;
}

static inline struct sk_buff *
dycbq_dequeue_1(struct Qdisc *sch)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	unsigned int activemask;

	activemask = q->activemask & 0xFF;
	while (activemask) {
		int prio = ffz(~activemask);
		activemask &= ~(1<<prio);
		skb = dycbq_dequeue_prio(sch, prio);
		if (skb)
			return skb;
	}
	return NULL;
}

static struct sk_buff *
dycbq_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	struct dycbq_sched_data *q = qdisc_priv(sch);
	psched_time_t now;
	psched_tdiff_t incr;

	now = psched_get_time();
	incr = now - q->now_rt;

	if (q->tx_class) {
		psched_tdiff_t incr2;
		incr2 = L2T(&q->link, q->tx_len);
		q->now += incr2;
		dycbq_update(q);
		if ((incr -= incr2) < 0)
			incr = 0;
		q->now += incr;
	} else {
		if (now > q->now)
			q->now = now;
	}
	q->now_rt = now;

	for (;;) {
		q->wd_expires = 0;

		skb = dycbq_dequeue_1(sch);
		if (skb) {
			qdisc_bstats_update(sch, skb);
			sch->q.qlen--;
			qdisc_unthrottled(sch);
			return skb;
		}

		/* All the classes are overlimit.
		 *
		 * It is possible, if:
		 *
		 * 1. Scheduler is empty.
		 * 2. Toplevel cutoff inhibited borrowing.
		 * 3. Root class is overlimit.
		 *
		 * Reset 2d and 3d conditions and retry.
		 *
		 * Note, that NS and cbq-2.0 are buggy, peeking
		 * an arbitrary class is appropriate for ancestor-only
		 * sharing, but not for toplevel algorithm.
		 *
		 * Our version is better, but slower, because it requires
		 * two passes, but it is unavoidable with top-level sharing.
		 */

		if (q->toplevel == TC_CBQ_MAXLEVEL &&
		    q->link.undertime == PSCHED_PASTPERFECT)
			break;

		q->toplevel = TC_CBQ_MAXLEVEL;
		q->link.undertime = PSCHED_PASTPERFECT;
	}

	if (sch->q.qlen) {
		sch->qstats.overlimits++;
		if (q->wd_expires)
			qdisc_watchdog_schedule(&q->watchdog,
						now + q->wd_expires);
	}
	return NULL;
}

/* CBQ class maintanance routines */

static void dycbq_adjust_levels(struct dycbq_class *this)
{
	if (this == NULL)
		return;

	do {
		int level = 0;
		struct dycbq_class *cl;

		cl = this->children;
		if (cl) {
			do {
				if (cl->level > level)
					level = cl->level;
			} while ((cl = cl->sibling) != this->children);
		}
		this->level = level + 1;
	} while ((this = this->tparent) != NULL);
}

static void dycbq_normalize_quanta(struct dycbq_sched_data *q, int prio)
{
	struct dycbq_class *cl;
	unsigned int h;

	if (q->quanta[prio] == 0)
		return;

	for (h = 0; h < q->clhash.hashsize; h++) {
		hlist_for_each_entry(cl, &q->clhash.hash[h], common.hnode) {

			if (cl->priority == prio) {
				cl->quantum = (cl->weight*cl->allot*q->nclasses[prio])/
					q->quanta[prio];
			}
			if (cl->quantum <= 0 || cl->quantum>32*qdisc_dev(cl->qdisc)->mtu) {
				pr_warning("CBQ: class %08x has bad quantum==%ld, repaired.\n",
					   cl->common.classid, cl->quantum);
				cl->quantum = qdisc_dev(cl->qdisc)->mtu/2 + 1;
			}
		}
	}
}

static void dycbq_sync_defmap(struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);
	struct dycbq_class *split = cl->split;
	unsigned int h;
	int i;

	if (split == NULL)
		return;

	for (i = 0; i <= TC_PRIO_MAX; i++) {
		if (split->defaults[i] == cl && !(cl->defmap & (1<<i)))
			split->defaults[i] = NULL;
	}

	for (i = 0; i <= TC_PRIO_MAX; i++) {
		int level = split->level;

		if (split->defaults[i])
			continue;

		for (h = 0; h < q->clhash.hashsize; h++) {
			struct dycbq_class *c;

			hlist_for_each_entry(c, &q->clhash.hash[h],
					     common.hnode) {
				if (c->split == split && c->level < level &&
				    c->defmap & (1<<i)) {
					split->defaults[i] = c;
					level = c->level;
				}
			}
		}
	}
}

static void dycbq_change_defmap(struct dycbq_class *cl, u32 splitid, u32 def, u32 mask)
{
	struct dycbq_class *split = NULL;

	if (splitid == 0) {
		split = cl->split;
		if (!split)
			return;
		splitid = split->common.classid;
	}

	if (split == NULL || split->common.classid != splitid) {
		for (split = cl->tparent; split; split = split->tparent)
			if (split->common.classid == splitid)
				break;
	}

	if (split == NULL)
		return;

	if (cl->split != split) {
		cl->defmap = 0;
		dycbq_sync_defmap(cl);
		cl->split = split;
		cl->defmap = def & mask;
	} else
		cl->defmap = (cl->defmap & ~mask) | (def & mask);

	dycbq_sync_defmap(cl);
}

static void dycbq_unlink_class(struct dycbq_class *this)
{
	struct dycbq_class *cl, **clp;
	struct dycbq_sched_data *q = qdisc_priv(this->qdisc);

	qdisc_class_hash_remove(&q->clhash, &this->common);
	if(this->tparent != NULL && this->tparent->classesAdded > 0){
		printk(KERN_DEBUG "A class has been removed -dycbq_unlink\n");
		this->tparent->classesAdded--;
	}
	if (this->tparent) {
		clp = &this->sibling;
		cl = *clp;
		do {
			if (cl == this) {
				*clp = cl->sibling;
				break;
			}
			clp = &cl->sibling;
		} while ((cl = *clp) != this->sibling);

		if (this->tparent->children == this) {
			this->tparent->children = this->sibling;
			if (this->sibling == this)
				this->tparent->children = NULL;
		}
	} else {
		WARN_ON(this->sibling != this);
	}
}

static void dycbq_link_class(struct dycbq_class *this)
{
//	printk(KERN_DEBUG "DYCBQ_LINKING_CLASS \n");
	struct dycbq_sched_data *q = qdisc_priv(this->qdisc);
	struct dycbq_class *parent = this->tparent;

	if(parent != NULL && parent->classesAdded == MAX_CHILD_CLASSES){
		printk(KERN_DEBUG "Cannot add more than 2 sub-classes \n");
		return;
	}

	this->sibling = this;
	qdisc_class_hash_insert(&q->clhash, &this->common);

	if (parent == NULL){
		printk("Parent is NULL since this is root\n");
		return;
	}
	if (parent->children == NULL) {
		parent->children = this;
	} else {
		this->sibling = parent->children->sibling;
		parent->children->sibling = this;
	}
	this->totalSharedSpace = parent->totalSharedSpace;
	this->borrow = NULL; 
	parent->classesAdded++;
	printk("Incremented classes added i.,e %d \n",parent->classesAdded);
}

static unsigned int dycbq_drop(struct Qdisc *sch)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl, *cl_head;
	int prio;
	unsigned int len;

	for (prio = TC_CBQ_MAXPRIO; prio >= 0; prio--) {
		cl_head = q->active[prio];
		if (!cl_head)
			continue;

		cl = cl_head;
		do {
			if (cl->q->ops->drop && (len = cl->q->ops->drop(cl->q))) {
				sch->q.qlen--;
				if (!cl->q->q.qlen)
					dycbq_deactivate_class(cl);
				return len;
			}
		} while ((cl = cl->next_alive) != cl_head);
	}
	return 0;
}

static void
dycbq_reset(struct Qdisc *sch)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl;
	int prio;
	unsigned int h;

	q->activemask = 0;
	q->pmask = 0;
	q->tx_class = NULL;
	q->tx_borrowed = NULL;
	qdisc_watchdog_cancel(&q->watchdog);
	hrtimer_cancel(&q->delay_timer);
	q->toplevel = TC_CBQ_MAXLEVEL;
	q->now = psched_get_time();
	q->now_rt = q->now;

	for (prio = 0; prio <= TC_CBQ_MAXPRIO; prio++)
		q->active[prio] = NULL;

	for (h = 0; h < q->clhash.hashsize; h++) {
		hlist_for_each_entry(cl, &q->clhash.hash[h], common.hnode) {
			qdisc_reset(cl->q);

			cl->next_alive = NULL;
			cl->undertime = PSCHED_PASTPERFECT;
			cl->avgidle = cl->maxidle;
			cl->deficit = cl->quantum;
			cl->cpriority = cl->priority;
		}
	}
	sch->q.qlen = 0;
}



static int dycbq_set_lss(struct dycbq_class *cl, struct tc_dycbq_lssopt *lss)
{
	if (lss->change & TCF_CBQ_LSS_FLAGS) {
		cl->share = (lss->flags & TCF_CBQ_LSS_ISOLATED) ? NULL : cl->tparent;
		cl->borrow = (lss->flags & TCF_DYCBQ_LSS_BOUNDED) ? NULL : cl->tparent;
	}
	if (lss->change & TCF_CBQ_LSS_EWMA)
		cl->ewma_log = lss->ewma_log;
	if (lss->change & TCF_CBQ_LSS_AVPKT)
		cl->avpkt = lss->avpkt;
	if (lss->change & TCF_CBQ_LSS_MINIDLE)
		cl->minidle = -(long)lss->minidle;
	if (lss->change & TCF_CBQ_LSS_MAXIDLE) {
		cl->maxidle = lss->maxidle;
		cl->avgidle = lss->maxidle;
	}
	if (lss->change & TCF_CBQ_LSS_OFFTIME)
		cl->offtime = lss->offtime;
	if (lss->limit) {
		printk("Setting Limit for class id=%x and limit=%d\n",cl->common.classid,lss->limit);
		cl->limit = lss->limit;
	}
	if (lss->variableSpace) {
		cl->variableSpace = lss->variableSpace;

		if(cl->variableSpace > cl->totalSharedSpace  && (cl->sibling == cl)){ //this is when it has no sibling
			cl->variableSpace = (u32)(cl->totalSharedSpace/2);
		} else if(cl->sibling && (cl->sibling != cl)){ //this is when it has sibling
			cl->variableSpace = (cl->totalSharedSpace - cl->sibling->variableSpace);
		}
		printk("Setting initial shared space for class id=%x and variableSpace=%d\n",cl->common.classid,cl->variableSpace);
	}
	if (lss->totalSharedSpace) {
		printk("For class id=%x Setting totalSharedSPace=%d\n",cl->common.classid,lss->totalSharedSpace);
		cl->totalSharedSpace = lss->totalSharedSpace;
	}
	cl->datareceived = 0;
	cl->datasent = 0;
	cl->dataDropped = 0;
	cl->packetsInVariableSpace = 0;
	cl->packetsDequeued = 0;
	cl->packetsDropped = 0;
	cl->packetsEnqueued = 0;
	return 0;
}

static void dycbq_rmprio(struct dycbq_sched_data *q, struct dycbq_class *cl)
{
	q->nclasses[cl->priority]--;
	q->quanta[cl->priority] -= cl->weight;
	dycbq_normalize_quanta(q, cl->priority);
}

static void dycbq_addprio(struct dycbq_sched_data *q, struct dycbq_class *cl)
{
	q->nclasses[cl->priority]++;
	q->quanta[cl->priority] += cl->weight;
	dycbq_normalize_quanta(q, cl->priority);
}

static int dycbq_set_wrr(struct dycbq_class *cl, struct tc_cbq_wrropt *wrr)
{
	struct dycbq_sched_data *q = qdisc_priv(cl->qdisc);

	if (wrr->allot)
		cl->allot = wrr->allot;
	if (wrr->weight)
		cl->weight = wrr->weight;
	if (wrr->priority) {
		cl->priority = wrr->priority - 1;
		cl->cpriority = cl->priority;
		if (cl->priority >= cl->priority2)
			cl->priority2 = TC_CBQ_MAXPRIO - 1;
	}

	dycbq_addprio(q, cl);
	return 0;
}

static int dycbq_set_overlimit(struct dycbq_class *cl, struct tc_cbq_ovl *ovl)
{
	switch (ovl->strategy) {
	case TC_CBQ_OVL_CLASSIC:
		cl->overlimit = dycbq_ovl_classic;
		break;
	case TC_CBQ_OVL_DELAY:
		cl->overlimit = dycbq_ovl_delay;
		break;
	case TC_CBQ_OVL_LOWPRIO:
		if (ovl->priority2 - 1 >= TC_CBQ_MAXPRIO ||
		    ovl->priority2 - 1 <= cl->priority)
			return -EINVAL;
		cl->priority2 = ovl->priority2 - 1;
		cl->overlimit = dycbq_ovl_lowprio;
		break;
	case TC_CBQ_OVL_DROP:
		cl->overlimit = dycbq_ovl_drop;
		break;
	case TC_CBQ_OVL_RCLASSIC:
		cl->overlimit = dycbq_ovl_rclassic;
		break;
	default:
		return -EINVAL;
	}
	cl->penalty = ovl->penalty;
	return 0;
}

#ifdef CONFIG_NET_CLS_ACT
static int dycbq_set_police(struct dycbq_class *cl, struct tc_cbq_police *p)
{
	cl->police = p->police;

	if (cl->q->handle) {
		if (p->police == TC_POLICE_RECLASSIFY)
			cl->q->reshape_fail = dycbq_reshape_fail;
		else
			cl->q->reshape_fail = NULL;
	}
	return 0;
}
#endif

static int dycbq_set_fopt(struct dycbq_class *cl, struct tc_cbq_fopt *fopt)
{
	dycbq_change_defmap(cl, fopt->split, fopt->defmap, fopt->defchange);
	return 0;
}



static const struct nla_policy dycbq_policy[TCA_DYCBQ_MAX + 1] = {
	[TCA_DYCBQ_LSSOPT]	= { .len = sizeof(struct tc_dycbq_lssopt) },
	[TCA_DYCBQ_WRROPT]	= { .len = sizeof(struct tc_cbq_wrropt) },
	[TCA_DYCBQ_FOPT]		= { .len = sizeof(struct tc_cbq_fopt) },
	[TCA_DYCBQ_OVL_STRATEGY]	= { .len = sizeof(struct tc_cbq_ovl) },
	[TCA_DYCBQ_RATE]		= { .len = sizeof(struct tc_ratespec) },
	[TCA_DYCBQ_RTAB]		= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
	[TCA_DYCBQ_POLICE]	= { .len = sizeof(struct tc_cbq_police) },
};

static int dycbq_init(struct Qdisc *sch, struct nlattr *opt)
{

	printk("Initializing DYCBQ\n");
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_DYCBQ_MAX + 1];
	struct tc_ratespec *r;
	int err;

	err = nla_parse_nested(tb, TCA_DYCBQ_MAX, opt, dycbq_policy);
	if (err < 0){
		printk("Error while parsing options\n");
		return err;
	}
	if (tb[TCA_DYCBQ_RTAB] == NULL || tb[TCA_DYCBQ_RATE] == NULL)
		return -EINVAL;

	r = nla_data(tb[TCA_DYCBQ_RATE]);

	if ((q->link.R_tab = qdisc_get_rtab(r, tb[TCA_DYCBQ_RTAB])) == NULL)
		return -EINVAL;

	err = qdisc_class_hash_init(&q->clhash);
	if (err < 0)
		goto put_rtab;

	q->link.refcnt = 1;
	q->link.sibling = &q->link;
	q->link.common.classid = sch->handle;
	q->link.qdisc = sch;
//	printk(KERN_DEBUG "Parent Queuing Discipline is %s",sch->ops->id);
	q->link.q = qdisc_create_dflt(sch->dev_queue, &dypfifo_qdisc_ops,
				      sch->handle);
	if (!q->link.q)
		q->link.q = &noop_qdisc;

	q->link.priority = TC_CBQ_MAXPRIO - 1;
	q->link.priority2 = TC_CBQ_MAXPRIO - 1;
	q->link.cpriority = TC_CBQ_MAXPRIO - 1;
	q->link.ovl_strategy = TC_CBQ_OVL_CLASSIC;
	q->link.overlimit = dycbq_ovl_classic;
	q->link.allot = psched_mtu(qdisc_dev(sch));
	q->link.quantum = q->link.allot;
	q->link.weight = q->link.R_tab->rate.rate;

	q->link.ewma_log = TC_CBQ_DEF_EWMA;
	q->link.avpkt = q->link.allot/2;
	q->link.minidle = -0x7FFFFFFF;
	q->link.limit = 1200;
	q->link.totalSharedSpace = 2000;
	q->link.variableSpace = 600;
	q->link.classesAdded = 0;
	q->link.packetsReceived = 0;
	qdisc_watchdog_init(&q->watchdog, sch);
	hrtimer_init(&q->delay_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	q->delay_timer.function = dycbq_undelay;
	q->toplevel = TC_CBQ_MAXLEVEL;
	q->now = psched_get_time();
	q->now_rt = q->now;
	printk(KERN_DEBUG "Linking Class to root\n");
	dycbq_link_class(&q->link);

	if (tb[TCA_DYCBQ_LSSOPT])
			dycbq_set_lss(&q->link, nla_data(tb[TCA_DYCBQ_LSSOPT]));

	dycbq_addprio(q, &q->link);
	return 0;

put_rtab:
	qdisc_put_rtab(q->link.R_tab);
	return err;
}

static int dycbq_dump_rate(struct sk_buff *skb, struct dycbq_class *cl)
{
	unsigned char *b = skb_tail_pointer(skb);

	if (nla_put(skb, TCA_DYCBQ_RATE, sizeof(cl->R_tab->rate), &cl->R_tab->rate))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int dycbq_dump_lss(struct sk_buff *skb, struct dycbq_class *cl)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_dycbq_lssopt opt;

	opt.flags = 0;
	if (cl->borrow == NULL)
		opt.flags |= TCF_DYCBQ_LSS_BOUNDED;
	if (cl->share == NULL)
		opt.flags |= TCF_CBQ_LSS_ISOLATED;
	opt.ewma_log = cl->ewma_log;
	opt.level = cl->level;
	opt.avpkt = cl->avpkt;
	opt.maxidle = cl->maxidle;
	opt.minidle = (u32)(-cl->minidle);
	opt.offtime = cl->offtime;
	opt.change = ~0;
	opt.limit = cl->limit;
	opt.variableSpace = cl->variableSpace;
	opt.totalSharedSpace = cl->totalSharedSpace;
	if (nla_put(skb, TCA_DYCBQ_LSSOPT, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int dycbq_dump_wrr(struct sk_buff *skb, struct dycbq_class *cl)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_cbq_wrropt opt;

	memset(&opt, 0, sizeof(opt));
	opt.flags = 0;
	opt.allot = cl->allot;
	opt.priority = cl->priority + 1;
	opt.cpriority = cl->cpriority + 1;
	opt.weight = cl->weight;
	if (nla_put(skb, TCA_DYCBQ_WRROPT, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int dycbq_dump_ovl(struct sk_buff *skb, struct dycbq_class *cl)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_cbq_ovl opt;

	opt.strategy = cl->ovl_strategy;
	opt.priority2 = cl->priority2 + 1;
	opt.pad = 0;
	opt.penalty = cl->penalty;
	if (nla_put(skb, TCA_DYCBQ_OVL_STRATEGY, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int dycbq_dump_fopt(struct sk_buff *skb, struct dycbq_class *cl)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_cbq_fopt opt;

	if (cl->split || cl->defmap) {
		opt.split = cl->split ? cl->split->common.classid : 0;
		opt.defmap = cl->defmap;
		opt.defchange = ~0;
		if (nla_put(skb, TCA_DYCBQ_FOPT, sizeof(opt), &opt))
			goto nla_put_failure;
	}
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

#ifdef CONFIG_NET_CLS_ACT
static int dycbq_dump_police(struct sk_buff *skb, struct dycbq_class *cl)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_cbq_police opt;

	if (cl->police) {
		opt.police = cl->police;
		opt.__res1 = 0;
		opt.__res2 = 0;
		if (nla_put(skb, TCA_DYCBQ_POLICE, sizeof(opt), &opt))
			goto nla_put_failure;
	}
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}
#endif

static int dycbq_dump_attr(struct sk_buff *skb, struct dycbq_class *cl)
{
	if (dycbq_dump_lss(skb, cl) < 0 ||
	    dycbq_dump_rate(skb, cl) < 0 ||
	    dycbq_dump_wrr(skb, cl) < 0 ||
	    dycbq_dump_ovl(skb, cl) < 0 ||
#ifdef CONFIG_NET_CLS_ACT
	    dycbq_dump_police(skb, cl) < 0 ||
#endif
	    dycbq_dump_fopt(skb, cl) < 0)
		return -1;
	return 0;
}

static int dycbq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	if (dycbq_dump_attr(skb, &q->link) < 0)
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static int
dycbq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);

	q->link.xstats.avgidle = q->link.avgidle;
	return gnet_stats_copy_app(d, &q->link.xstats, sizeof(q->link.xstats));
}

static int
dycbq_dump_class(struct Qdisc *sch, unsigned long arg,
	       struct sk_buff *skb, struct tcmsg *tcm)
{
	struct dycbq_class *cl = (struct dycbq_class *)arg;
	struct nlattr *nest;

	if (cl->tparent)
		tcm->tcm_parent = cl->tparent->common.classid;
	else
		tcm->tcm_parent = TC_H_ROOT;
	tcm->tcm_handle = cl->common.classid;
	tcm->tcm_info = cl->q->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	if (dycbq_dump_attr(skb, cl) < 0)
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static int
dycbq_dump_class_stats(struct Qdisc *sch, unsigned long arg,
	struct gnet_dump *d)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	cl->qstats.qlen = cl->q->q.qlen;
	cl->xstats.avgidle = cl->avgidle;
	cl->xstats.undertime = 0;

	if (cl->undertime != PSCHED_PASTPERFECT)
		cl->xstats.undertime = cl->undertime - q->now;

	if (gnet_stats_copy_basic(d, &cl->bstats) < 0 ||
	    gnet_stats_copy_rate_est(d, &cl->bstats, &cl->rate_est) < 0 ||
	    gnet_stats_copy_queue(d, &cl->qstats) < 0)
		return -1;

	return gnet_stats_copy_app(d, &cl->xstats, sizeof(cl->xstats));
}

static int dycbq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	if (new == NULL) {
		new = qdisc_create_dflt(sch->dev_queue,
					&dypfifo_qdisc_ops, cl->common.classid);
		if (new == NULL)
			return -ENOBUFS;
	} else {
#ifdef CONFIG_NET_CLS_ACT
		if (cl->police == TC_POLICE_RECLASSIFY)
			new->reshape_fail = dycbq_reshape_fail;
#endif
	}
	sch_tree_lock(sch);
	*old = cl->q;
	cl->q = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	return 0;
}

static struct Qdisc *dycbq_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	return cl->q;
}

static void dycbq_qlen_notify(struct Qdisc *sch, unsigned long arg)
{
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	if (cl->q->q.qlen == 0)
		dycbq_deactivate_class(cl);
}

static unsigned long dycbq_get(struct Qdisc *sch, u32 classid)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl = dycbq_class_lookup(q, classid);

	if (cl) {
		cl->refcnt++;
		return (unsigned long)cl;
	}
	return 0;
}

static void dycbq_destroy_class(struct Qdisc *sch, struct dycbq_class *cl)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);

	WARN_ON(cl->filters);

	tcf_destroy_chain(&cl->filter_list);
	qdisc_destroy(cl->q);
	qdisc_put_rtab(cl->R_tab);
	gen_kill_estimator(&cl->bstats, &cl->rate_est);
	if (cl != &q->link)
		kfree(cl);
}

static void dycbq_destroy(struct Qdisc *sch)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct hlist_node *next;
	struct dycbq_class *cl;
	unsigned int h;

#ifdef CONFIG_NET_CLS_ACT
	q->rx_class = NULL;
#endif
	/*
	 * Filters must be destroyed first because we don't destroy the
	 * classes from root to leafs which means that filters can still
	 * be bound to classes which have been destroyed already. --TGR '04
	 */
	for (h = 0; h < q->clhash.hashsize; h++) {
		hlist_for_each_entry(cl, &q->clhash.hash[h], common.hnode)
			tcf_destroy_chain(&cl->filter_list);
	}
	for (h = 0; h < q->clhash.hashsize; h++) {
		hlist_for_each_entry_safe(cl, next, &q->clhash.hash[h],
					  common.hnode)
			dycbq_destroy_class(sch, cl);
	}
	qdisc_class_hash_destroy(&q->clhash);
}

static void dycbq_put(struct Qdisc *sch, unsigned long arg)
{
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	if (--cl->refcnt == 0) {
#ifdef CONFIG_NET_CLS_ACT
		spinlock_t *root_lock = qdisc_root_sleeping_lock(sch);
		struct dycbq_sched_data *q = qdisc_priv(sch);

		spin_lock_bh(root_lock);
		if (q->rx_class == cl)
			q->rx_class = NULL;
		spin_unlock_bh(root_lock);
#endif

		dycbq_destroy_class(sch, cl);
	}
}

static int
dycbq_change_class(struct Qdisc *sch, u32 classid, u32 parentid, struct nlattr **tca,
		 unsigned long *arg)
{
	printk(KERN_DEBUG "Linking Child Class to root\n");
	int err;
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl = (struct dycbq_class *)*arg;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_DYCBQ_MAX + 1];
	struct dycbq_class *parent;
	struct qdisc_rate_table *rtab = NULL;

	if (opt == NULL){
		printk("OPT is null\n");
		return -EINVAL;
	}
	err = nla_parse_nested(tb, TCA_DYCBQ_MAX, opt, dycbq_policy);
	if (err < 0){
		printk("Error while parsing\n");
		return err;
	}
	if (cl) {
		/* Check parent */
		printk("Linking Class - It is class\n");
		if (parentid) {
			if (cl->tparent &&
			    cl->tparent->common.classid != parentid)
				return -EINVAL;
			if (!cl->tparent && parentid != TC_H_ROOT)
				return -EINVAL;
		}

		if (tb[TCA_DYCBQ_RATE]) {
			rtab = qdisc_get_rtab(nla_data(tb[TCA_DYCBQ_RATE]),
					      tb[TCA_DYCBQ_RTAB]);
			if (rtab == NULL)
				return -EINVAL;
		}

		if (tca[TCA_RATE]) {
			err = gen_replace_estimator(&cl->bstats, &cl->rate_est,
						    qdisc_root_sleeping_lock(sch),
						    tca[TCA_RATE]);
			if (err) {
				if (rtab)
					qdisc_put_rtab(rtab);
				return err;
			}
		}

		/* Change class parameters */
		sch_tree_lock(sch);

		if (cl->next_alive != NULL)
			dycbq_deactivate_class(cl);

		if (rtab) {
			qdisc_put_rtab(cl->R_tab);
			cl->R_tab = rtab;
		}

		if (tb[TCA_DYCBQ_LSSOPT]){
			printk("LInking class - setting dycbq lss opts");
			dycbq_set_lss(cl, nla_data(tb[TCA_DYCBQ_LSSOPT]));
		}
		if (tb[TCA_DYCBQ_WRROPT]) {
			dycbq_rmprio(q, cl);
			dycbq_set_wrr(cl, nla_data(tb[TCA_DYCBQ_WRROPT]));
		}

		if (tb[TCA_DYCBQ_OVL_STRATEGY])
			dycbq_set_overlimit(cl, nla_data(tb[TCA_DYCBQ_OVL_STRATEGY]));

#ifdef CONFIG_NET_CLS_ACT
		if (tb[TCA_DYCBQ_POLICE])
			dycbq_set_police(cl, nla_data(tb[TCA_DYCBQ_POLICE]));
#endif

		if (tb[TCA_DYCBQ_FOPT])
			dycbq_set_fopt(cl, nla_data(tb[TCA_DYCBQ_FOPT]));

		if (cl->q->q.qlen)
			dycbq_activate_class(cl);

		sch_tree_unlock(sch);

		return 0;
	}

	if (parentid == TC_H_ROOT)
		return -EINVAL;

	if (tb[TCA_DYCBQ_WRROPT] == NULL || tb[TCA_DYCBQ_RATE] == NULL ||
	    tb[TCA_DYCBQ_LSSOPT] == NULL)
		return -EINVAL;

	rtab = qdisc_get_rtab(nla_data(tb[TCA_DYCBQ_RATE]), tb[TCA_DYCBQ_RTAB]);
	if (rtab == NULL)
		return -EINVAL;

	if (classid) {
		err = -EINVAL;
		if (TC_H_MAJ(classid ^ sch->handle) ||
		    dycbq_class_lookup(q, classid))
			goto failure;
	} else {
		int i;
		classid = TC_H_MAKE(sch->handle, 0x8000);

		for (i = 0; i < 0x8000; i++) {
			if (++q->hgenerator >= 0x8000)
				q->hgenerator = 1;
			if (dycbq_class_lookup(q, classid|q->hgenerator) == NULL)
				break;
		}
		err = -ENOSR;
		if (i >= 0x8000)
			goto failure;
		classid = classid|q->hgenerator;
	}

	parent = &q->link;
	if (parentid) {
		parent = dycbq_class_lookup(q, parentid);
		err = -EINVAL;
		if (parent == NULL)
			goto failure;
	}

	err = -ENOBUFS;
	cl = kzalloc(sizeof(*cl), GFP_KERNEL);
	if (cl == NULL)
		goto failure;

	if (tca[TCA_RATE]) {
		err = gen_new_estimator(&cl->bstats, &cl->rate_est,
					qdisc_root_sleeping_lock(sch),
					tca[TCA_RATE]);
		if (err) {
			kfree(cl);
			goto failure;
		}
	}

	cl->R_tab = rtab;
	rtab = NULL;
	cl->refcnt = 1;
	cl->q = qdisc_create_dflt(sch->dev_queue, &dypfifo_qdisc_ops, classid);
	if (!cl->q)
		cl->q = &noop_qdisc;
	cl->common.classid = classid;
	cl->tparent = parent;
	cl->qdisc = sch;
	cl->allot = parent->allot;
	cl->quantum = cl->allot;
	cl->weight = cl->R_tab->rate.rate;

	sch_tree_lock(sch);
	dycbq_link_class(cl);
	cl->borrow = cl->tparent;
	if (cl->tparent != &q->link)
		cl->share = cl->tparent;
	dycbq_adjust_levels(parent);
	cl->minidle = -0x7FFFFFFF;
	dycbq_set_lss(cl, nla_data(tb[TCA_DYCBQ_LSSOPT]));
	dycbq_set_wrr(cl, nla_data(tb[TCA_DYCBQ_WRROPT]));
	if (cl->ewma_log == 0)
		cl->ewma_log = q->link.ewma_log;
	if (cl->maxidle == 0)
		cl->maxidle = q->link.maxidle;
	if (cl->avpkt == 0)
		cl->avpkt = q->link.avpkt;
	if (cl->limit == 0)
		cl->limit = q->link.limit;
	if (cl->variableSpace == 0)
		cl->variableSpace = q->link.variableSpace;
	if (cl->totalSharedSpace == 0)
		cl->totalSharedSpace = q->link.totalSharedSpace;
	cl->overlimit = dycbq_ovl_classic;
	if (tb[TCA_DYCBQ_OVL_STRATEGY])
		dycbq_set_overlimit(cl, nla_data(tb[TCA_DYCBQ_OVL_STRATEGY]));
#ifdef CONFIG_NET_CLS_ACT
	if (tb[TCA_DYCBQ_POLICE])
		dycbq_set_police(cl, nla_data(tb[TCA_DYCBQ_POLICE]));
#endif
	if (tb[TCA_DYCBQ_FOPT])
		dycbq_set_fopt(cl, nla_data(tb[TCA_DYCBQ_FOPT]));
	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &q->clhash);

	*arg = (unsigned long)cl;
	return 0;

failure:
	qdisc_put_rtab(rtab);
	return err;
}

static int dycbq_delete(struct Qdisc *sch, unsigned long arg)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl = (struct dycbq_class *)arg;
	unsigned int qlen;

	if (cl->filters || cl->children || cl == &q->link)
		return -EBUSY;

	sch_tree_lock(sch);

	qlen = cl->q->q.qlen;
	qdisc_reset(cl->q);
	qdisc_tree_decrease_qlen(cl->q, qlen);

	if (cl->next_alive)
		dycbq_deactivate_class(cl);

	if (q->tx_borrowed == cl)
		q->tx_borrowed = q->tx_class;
	if (q->tx_class == cl) {
		q->tx_class = NULL;
		q->tx_borrowed = NULL;
	}
#ifdef CONFIG_NET_CLS_ACT
	if (q->rx_class == cl)
		q->rx_class = NULL;
#endif

	dycbq_unlink_class(cl);
	dycbq_adjust_levels(cl->tparent);
	cl->defmap = 0;
	dycbq_sync_defmap(cl);

	dycbq_rmprio(q, cl);
	sch_tree_unlock(sch);

	BUG_ON(--cl->refcnt == 0);
	/*
	 * This shouldn't happen: we "hold" one cops->get() when called
	 * from tc_ctl_tclass; the destroy method is done from cops->put().
	 */

	return 0;
}

static struct tcf_proto **dycbq_find_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	if (cl == NULL)
		cl = &q->link;

	return &cl->filter_list;
}

static unsigned long dycbq_bind_filter(struct Qdisc *sch, unsigned long parent,
				     u32 classid)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *p = (struct dycbq_class *)parent;
	struct dycbq_class *cl = dycbq_class_lookup(q, classid);

	if (cl) {
		if (p && p->level <= cl->level)
			return 0;
		cl->filters++;
		return (unsigned long)cl;
	}
	return 0;
}

static void dycbq_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct dycbq_class *cl = (struct dycbq_class *)arg;

	cl->filters--;
}

static void dycbq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct dycbq_sched_data *q = qdisc_priv(sch);
	struct dycbq_class *cl;
	unsigned int h;

	if (arg->stop)
		return;

	for (h = 0; h < q->clhash.hashsize; h++) {
		hlist_for_each_entry(cl, &q->clhash.hash[h], common.hnode) {
			if (arg->count < arg->skip) {
				arg->count++;
				continue;
			}
			if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
				arg->stop = 1;
				return;
			}
			arg->count++;
		}
	}
}

static const struct Qdisc_class_ops dycbq_class_ops = {
	.graft		=	dycbq_graft,
	.leaf		=	dycbq_leaf,
	.qlen_notify	=	dycbq_qlen_notify,
	.get		=	dycbq_get,
	.put		=	dycbq_put,
	.change		=	dycbq_change_class,
	.delete		=	dycbq_delete,
	.walk		=	dycbq_walk,
	.tcf_chain	=	dycbq_find_tcf,
	.bind_tcf	=	dycbq_bind_filter,
	.unbind_tcf	=	dycbq_unbind_filter,
	.dump		=	dycbq_dump_class,
	.dump_stats	=	dycbq_dump_class_stats,
};

static struct Qdisc_ops dycbq_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	&dycbq_class_ops,
	.id			=	"dycbq",
	.priv_size	=	sizeof(struct dycbq_sched_data),
	.enqueue	=	dycbq_enqueue,
	.dequeue	=	dycbq_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.drop		=	dycbq_drop,
	.init		=	dycbq_init,
	.reset		=	dycbq_reset,
	.destroy	=	dycbq_destroy,
	.change		=	NULL,
	.dump		=	dycbq_dump,
	.dump_stats	=	dycbq_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init dycbq_module_init(void)
{
	return register_qdisc(&dycbq_qdisc_ops);
}
static void __exit dycbq_module_exit(void)
{
	unregister_qdisc(&dycbq_qdisc_ops);
}
module_init(dycbq_module_init)
module_exit(dycbq_module_exit)
MODULE_LICENSE("GPL");
