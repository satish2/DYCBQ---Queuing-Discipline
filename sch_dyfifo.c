/*
 * Reference : <linux_kernel_sources>/net/sched/sch_fifo.c and <linux_kernel_sources>/net/sched/sch_cbq.c
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/*
 * DY_CBQ Struct : this is same as struct defined in sch_dycbq.c file.
 */
struct dycbq_class {
	struct Qdisc_class_common common;
	struct dycbq_class	*next_alive;	/* next class according to priority that has packets ready to be sent */

/* Parameters */
	unsigned char		priority;	/* priority of this class */
	unsigned char		priority2;	/* priority to be used after overlimit which is used  */
	unsigned char		ewma_log;	/* time constant for idle time calculation */
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
	long			quantum;	/* Allotment per WRR round */
	long			weight;		/* Relative allotment: see below */

	struct Qdisc		*qdisc;		/* Ptr to DYCBQ discipline */
	struct dycbq_class	*split;		/* Ptr to split node */
	struct dycbq_class	*share;		/* Ptr to LS parent in the class tree */
	struct dycbq_class	*tparent;	/* Ptr to tree parent in the class tree */
	struct dycbq_class	*borrow;	/* NULL if class is bandwidth limited;
						   parent otherwise */
	struct dycbq_class	*sibling;	/* Sibling chain */
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
 * This contains the algorithm which defines how shared space is allocated to each based on incoming traffic.
 */
static int adjustSharedSpace(struct dycbq_class *platinumCls, struct dycbq_class *regularCls) {
	if (platinumCls != regularCls && platinumCls->packetsReceived + regularCls->packetsReceived > 50 && platinumCls->packetsReceived + regularCls->packetsReceived < 55) { 
	//platinumCls != regularCls - they can be equal if root has only one class
		printk("***********META DATA FOR EACH CLASS AFTER 50 PACKETS HAVE BEEN RECEIVED BY BOTH CLASSES *************\n");
		printk("CLASS ID:%x is PLATINUM \n", platinumCls->common.classid);
		printk("Before Adjusting: Regular Variable Space = %d, Platinum Variable Space = %d\n", regularCls->variableSpace, platinumCls->variableSpace);
		bool withinFixedLimit = true;
		u32 freeSpace;
		u32 totalSharedSpace = regularCls->totalSharedSpace;
		struct Qdisc *sch1 = platinumCls->q;
		struct Qdisc *sch2 = regularCls->q;
		int platinumOccupancy = skb_queue_len(&sch1->q);
		int regularOccupancy = skb_queue_len(&sch2->q);
		bool isPlatinShared = platinumOccupancy > platinumCls->limit;
		bool isRegShared = regularOccupancy > regularCls->limit;
		withinFixedLimit = !(isPlatinShared || isRegShared);
		int pt_oldVariableSpace = platinumCls->variableSpace;
		int rg_oldVariableSpace = regularCls->variableSpace;

		if (withinFixedLimit || (isPlatinShared && !isRegShared)) {
		/*
			 * When none of both classes is using shared space or only platinum is using shared space, then we are increasing 
			 * shared space allotted to platinum from regular by taking from initial allotted shared space of regular
			 * 1. If platinumOccupancy(no.of packets in platinum queue) is more than regularOccupancy, then 2/3 of regular's shared space is
			 * 	  added to platinum
			 * 2. If platinumOccupancy is less than regularOccupancy, then adding 1/4 of platinum to regular. But it may happen that platinum total
			 *    allocation is less than occupied. Then we will revert to old parititioning of shared space.
		* */
			if (platinumOccupancy >= regularOccupancy) {
				platinumCls->variableSpace = platinumCls->variableSpace + (u32)((2 * (regularCls->variableSpace) / 3));
				regularCls->variableSpace = totalSharedSpace - platinumCls->variableSpace;
			} else {
				regularCls->variableSpace = regularCls->variableSpace + (u32)((1 * (platinumCls->variableSpace) / 4));
				platinumCls->variableSpace = totalSharedSpace - regularCls->variableSpace;
			}
		} else if (isRegShared && !isPlatinShared) {
			/*
			 * Here platinum is not using shared, but regular is. In this case we will increment regular's allotted space, but
			 * rather than space from platinum's shared area, we will add from available free. This can result in
			 * less than inital variableSpace available for regular paving way for burst traffic from platinum.
			 * */
			freeSpace = totalSharedSpace - regularCls->packetsInVariableSpace;
			regularCls->variableSpace = regularOccupancy - regularCls->limit + (u32)((freeSpace) / 4);
			platinumCls->variableSpace = totalSharedSpace - regularCls->variableSpace;
		} else {
			/*
			 * Here there is a contention for sharedspace from both the classes.
			 * Based on occupancy of both classes, we are allocation either 3/4 of available free space to platinum (ptOccupancy > rgOccupancy)
			 * or
			 * 1/3 of available free-space to regular and rest of free-space to platinum.
			 * */
			freeSpace = totalSharedSpace - platinumCls->packetsInVariableSpace - regularCls->packetsInVariableSpace; 
			//One of the classes is using shared space and platinum packets are more than regular packets.
			if (platinumOccupancy >= regularOccupancy) { //within 51 packets more platinum has come and less regular
				platinumCls->variableSpace = platinumCls->packetsInVariableSpace + (u32)((3) * (freeSpace) / 4);
				regularCls->variableSpace = totalSharedSpace - platinumCls->variableSpace;
			} else {
				regularCls->variableSpace = regularCls->packetsInVariableSpace + (u32)((freeSpace) / 3);
				platinumCls->variableSpace = totalSharedSpace - regularCls->variableSpace;
			}
		}
		if(platinumOccupancy > platinumCls->limit+platinumCls->variableSpace || regularOccupancy > regularCls->limit+regularCls->variableSpace){
			platinumCls->variableSpace = pt_oldVariableSpace;
			regularCls->variableSpace = rg_oldVariableSpace;
		}
		if (platinumCls->variableSpace < 0 || regularCls->variableSpace < 0){
			platinumCls->variableSpace = pt_oldVariableSpace;
			regularCls->variableSpace = rg_oldVariableSpace;
		}
		printk("After Adjusting: Regular Variable Space = %d, Platinum Variable Space = %d\n", regularCls->variableSpace, platinumCls->variableSpace);
		return 0;
	} 
	if (platinumCls->packetsReceived + regularCls->packetsReceived >= 55 ){
		platinumCls->packetsReceived = 0;
		regularCls->packetsReceived = 0;
		return -1; //One of the classes failed to get fair chance to access this function
	}
	return -1;
}

/*
 * This function is called whenever a packet is to be enqueued into FIFO queue.
 * First function checks if the total packets received are more than 50 from both classes. If it is, it adjusts the space and
 * enqueues new packet. Else, it will continue to enqueue in already allocated space (dedicated/shared based on occupancy).
 * If occupancy is more than dedicated + allocated shared space, then packets are dropped. Dropped packets are logged.
 */

int dypfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct dycbq_class *cl) {
	int retVal = -1;
	if (likely(skb_queue_len(&sch->q) < cl->limit)) {
		cl->packetsInVariableSpace = 0;

		if (cl->priority <= cl->sibling->priority){ // this means cl has more priority than cl->sibling
			retVal = adjustSharedSpace(cl, cl->sibling);
			if(retVal == 0){
				printPacketDetails(skb, cl, sch);
				cl->packetsReceived = 0;
				cl->sibling->packetsReceived = 0;
			}
		}
		else{
			retVal = adjustSharedSpace(cl->sibling, cl);//when current class in which packets are enqueued is not platinum
			if(retVal == 0){
				printPacketDetails(skb, cl->sibling, cl->sibling->q);
				cl->packetsReceived = 0;
				cl->sibling->packetsReceived = 0;
			}
		}

		cl->packetsEnqueued++;
		cl->datareceived = cl->datareceived + skb->len;
		return qdisc_enqueue_tail(skb, sch);
	} else if (likely(skb_queue_len(&sch->q) < cl->limit + cl->variableSpace)) {
		cl->packetsInVariableSpace = skb_queue_len(&sch->q) - cl->limit;

		if (cl->priority <= cl->sibling->priority) {// this means cl has more priority than cl->sibling
			retVal = adjustSharedSpace(cl, cl->sibling);
			if(retVal == 0){
				printPacketDetails(skb, cl, sch);
				cl->packetsReceived = 0;
				cl->sibling->packetsReceived = 0;
			}
		}
		else {
			retVal = adjustSharedSpace(cl->sibling, cl);//when current class in which packets are enqueued is not platinum
			if(retVal == 0){
				printPacketDetails(skb, cl->sibling, cl->sibling->q);
				cl->packetsReceived = 0;
				cl->sibling->packetsReceived = 0;
			}
		}
		cl->packetsEnqueued++;
		cl->datareceived = cl->datareceived + skb->len;
		return qdisc_enqueue_tail(skb, sch);
	}

	cl->packetsDropped++;
	cl->dataDropped=cl->dataDropped + skb->len;

	return qdisc_reshape_fail(skb, sch);

drop:
	return qdisc_reshape_fail(skb, sch);
}
EXPORT_SYMBOL(dypfifo_enqueue);

/*
 * This function is called while dequeuing packets from fifo queue
 * Uses same dequeuing method as FIFO and calls __qdisc_dequeue_head method in sch_generic.c
 */
static inline struct sk_buff *dyfifo_dequeue_head(struct Qdisc *sch) {
	struct sk_buff *skb = __qdisc_dequeue_head(sch, &sch->q);
	return skb;
}

/*
 * Whenever a packet dequeue is occuring from a class, this method is called from sch_dycbq.c.
 * This function has to be exposed or else increments made in sch_dycbq are not visible to functions in sch_dyfifo
 */
void incrementDequeue(struct dycbq_class *cl){
	cl->packetsDequeued++;
}
EXPORT_SYMBOL(incrementDequeue);

/*
 * This prints the information for every adjustment in variable space that was made
 * It logs cumulative data (data from when the class was added till now) and also specific data i.,e
 * For every 50 packets, packets received by each class, maximum limit after adjustment, packets in shared space are logged.
 */
void printPacketDetails(struct sk_buff *skb, struct dycbq_class *cl, struct Qdisc *sch) {
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);

	if(cl->tparent == NULL){
		return; //Not printing packets handled by root class.
	}

	if (!ip_header) {
		printk("IP HEADER IS NULL\n");
	}

	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct icmphdr* icmp;
	struct Qdisc *sch1 = cl->sibling->q;
	unsigned int src_ip = (unsigned int) ip_header->saddr;
	unsigned int dest_ip = (unsigned int) ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;

	printk("CLASS ID: %x \n",cl->common.classid);
	printk("Occupancy: %d, Max_Length=%d,FixedSpace=%d, PacketsReceived=%d\n",skb_queue_len(&sch->q), (cl->limit + cl->variableSpace),cl->limit,cl->packetsReceived);
	printk("Packets in SharedSpace = %d\n",cl->packetsInVariableSpace);
	printk("This is Cumulative Data of %x\n",cl->common.classid);
	printk("Enqueued=%d,Dequeued=%d,Dropped=%d,Data_Received=%llu,Data_sent=%llu,Data_Dropped=%llu (in bytes)\n",cl->packetsEnqueued,cl->packetsDequeued,cl->packetsDropped,cl->datareceived,cl->datasent,cl->dataDropped);
	printk("------------------------------------------------------------------------------------------------------\n");
	printk("CLASS ID: %x \n",cl->sibling->common.classid);
	printk("Occupancy: %d, Max_Length=%d,FixedSpace=%d, PacketsReceived=%d\n",skb_queue_len(&sch1->q), (cl->sibling->limit + cl->sibling->variableSpace),cl->sibling->limit,cl->sibling->packetsReceived);
	printk("Packets in SharedSpace = %d\n",cl->sibling->packetsInVariableSpace);
	printk("This is Cumulative Data of %x\n",cl->sibling->common.classid);
	printk("Enqueued=%d,Dequeued=%d,Dropped=%d, Data_Received=%llu,Data_sent=%llu,Data_Dropped=%llu (in bytes)\n",cl->sibling->packetsEnqueued,cl->sibling->packetsDequeued,cl->sibling->packetsDropped, cl->sibling->datareceived,cl->sibling->datasent,cl->sibling->dataDropped);
	printk("csv:%d,%d,%d,%d,%d,%d\n",cl->packetsReceived,skb_queue_len(&sch->q),cl->limit + cl->variableSpace,cl->sibling->packetsReceived,skb_queue_len(&sch1->q),(cl->sibling->limit + cl->sibling->variableSpace));
	printk("*****************************************END**********************************************\n\n");

	sch->limit = (cl->limit + cl->variableSpace);
	sch1->limit = (cl->sibling->limit + cl->sibling->variableSpace);
/*	if (isDropped) {
		printk("Dropped: Class_id=%x", cl->common.classid);
		printk("Occupancy=%d, Max_Length=%d DroppedTillNow=%d", skb_queue_len(&sch->q), (cl->limit + cl->variableSpace),cl->packetsDropped);
	} else if (isEnqueue && isVariable) {
		printk("Enqueued in Variable Space: Class_id=%x", cl->common.classid);
		printk("Occupancy=%d, Max_Length=%d PacketsOfThisClass = %d ", skb_queue_len(&sch->q), (cl->limit + cl->variableSpace), cl->packetsReceived);
	} else if (isEnqueue) {
		printk("Enqueued: Class_id=%x", cl->common.classid);
		printk("Occupancy=%d, Max_Length=%d PacketsOfThisClass = %d ", skb_queue_len(&sch->q), (cl->limit + cl->variableSpace), cl->packetsReceived);
	} else {
		printk("Dequeued: Class_id=%x", cl->common.classid);
		printk("Occupancy=%d, Max_Length=%d DequeuedTillNow=%d", (skb_queue_len(&sch->q)-1), (cl->limit + cl->variableSpace),cl->packetsDequeued);
	}*/
/*	if (ip_header->protocol == 17) {	//checks for UDP Packets
		udp_header = (struct udphdr *) skb_transport_header(skb);	//extracts UDP Header from packet
		src_port = (unsigned int) ntohs(udp_header->source);
		dest_port = (unsigned int) ntohs(udp_header->dest);
		printk("protocol:UDP");
		printIPAddress(src_ip, true);
		printIPAddress(dest_ip, false);
		printk("packet_length:%d\n", skb->len);

	} else if (ip_header->protocol == 6) {
		tcp_header = (struct tcphdr *) skb_transport_header(skb);	//extract TCP Header from packet
		src_port = (unsigned int) ntohs(tcp_header->source);
		dest_port = (unsigned int) ntohs(tcp_header->dest);
		printk("protocol:TCP");
		printIPAddress(src_ip, true);
		printIPAddress(dest_ip, false);
		printk("packet_length:%d\n", skb->len);

	} else if (ip_header->protocol == 1) {
		icmp = (struct icmphdr*) ((char*) ip_header + sizeof(struct iphdr));		//extracts header from ICMP Packet
		printk("protocol:ICMP");
		printIPAddress(src_ip, true);
		printIPAddress(dest_ip, false);
		printk("packet_length:%d\n", skb->len);
	} else {
		printk("protocol:%d",ip_header->protocol);
		printIPAddress(src_ip, true);
		printIPAddress(dest_ip, false);
		printk("packet_length:%d\n", skb->len);//qdisc_pkt_len(skb)
	}*/
}
//EXPORT_SYMBOL(printPacketDetails);

/*void printIPAddress(unsigned int ipAddress, bool isSourceAddress) {

	unsigned char octet[4] = { 0, 0, 0, 0 };
	int i;
	for (i = 0; i < 4; i++) {
		octet[i] = (ipAddress >> (i * 8)) & 0xFF;
	}
	if (isSourceAddress)
		printk(" srcIP=%d.%d.%d.%d ", octet[0], octet[1], octet[2], octet[3]);
	else
		printk(" destIP=%d.%d.%d.%d ", octet[0], octet[1], octet[2], octet[3]);

}*/

static int dyfifo_init(struct Qdisc *sch, struct nlattr *opt) {
	return 0;
}
/*
 * This method is classes when tc -s -d class show dev <serverInterface> is called, logs all the options of dyfifo.
 * This prints the total fifo length ( dedicated + shared)
*/
static int dyfifo_dump(struct Qdisc *sch, struct sk_buff *skb) {
	struct tc_fifo_qopt opt = { .limit = sch->limit };

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

	nla_put_failure: return -1;
}

struct Qdisc_ops dypfifo_qdisc_ops __read_mostly = {
		.id = "dypfifo",
		.priv_size = 0,
		.enqueue = dypfifo_enqueue,
		.dequeue = dyfifo_dequeue_head,
		.peek = qdisc_peek_head,
		.drop =	qdisc_queue_drop,
		.init = dyfifo_init,
		.reset = qdisc_reset_queue,
		.change = dyfifo_init,
		.dump = dyfifo_dump,
		.owner = THIS_MODULE,
};
EXPORT_SYMBOL(dypfifo_qdisc_ops);
