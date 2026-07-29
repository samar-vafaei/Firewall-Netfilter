#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "logger.h"
#include "packet_parser.h"
#include "rule_engine.h"


static struct nf_hook_ops *nf_logIPpacket_ops = NULL;


static unsigned int nf_logIPpacket_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	if(!skb)
		return NF_ACCEPT;

	struct packet_info pkt = {};

	if(!parse_packet(skb, &pkt))
		return NF_DROP;

	enum fw_action action;
	action = fw_match_packet(&pkt);

	logger(&pkt);

	//return NF_ACCEPT;
	return action;
}


static int __init nf_logIPpacket_init(void){

	nf_logIPpacket_ops = (struct nf_hook_ops*)kcalloc(1,sizeof(struct nf_hook_ops),GFP_KERNEL);
	
	if(nf_logIPpacket_ops != NULL){

		nf_logIPpacket_ops->hook = (nf_hookfn*)nf_logIPpacket_handler;
		nf_logIPpacket_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_logIPpacket_ops->pf = NFPROTO_IPV4;
		nf_logIPpacket_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_logIPpacket_ops);
	}

	return 0;
}

static void __exit nf_logIPpacket_exit(void){

	if(nf_logIPpacket_ops != NULL){
		nf_unregister_net_hook(&init_net, nf_logIPpacket_ops);
		kfree(nf_logIPpacket_ops);
	}

	printk(KERN_INFO "The module is released.");
}

module_init(nf_logIPpacket_init);
module_exit(nf_logIPpacket_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samar");
MODULE_DESCRIPTION("Firewall using Netfilter");
MODULE_VERSION("1.0");
