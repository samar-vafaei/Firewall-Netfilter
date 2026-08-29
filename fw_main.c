#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/genetlink.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "logger.h"
#include "packet_parser.h"
#include "rule_engine.h"


enum fw_cmd {

	FW_CMD_UNSPEC,

	FW_CMD_ADD_RULE,
	FW_CMD_DELETE_RULE,
	FW_CMD_UPDATE_RULE,
	FW_CMD_LIST_RULE,

	__FW_CMD_MAX,
};

#define FW_CMD_MAX (__FW_CMD_MAX - 1)

enum fw_attr {

	FW_ATTR_UNSPEC,

	FW_ATTR_SRC_IP,
	FW_ATTR_DST_IP,
	FW_ATTR_SRC_PORT,
	FW_ATTR_DST_PORT,
	FW_ATTR_PROTOCOL,
	FW_ATTR_ACTION,

	__FW_ATTR_MAX,
};

#define FW_ATTR_MAX (__FW_ATTR_MAX - 1)

static struct nf_hook_ops *nf_logIPpacket_ops = NULL;

static const struct nla_policy fw_policy[FW_ATTR_MAX + 1] = {

	[FW_ATTR_SRC_IP] = {

		.type = NLA_U32,
	},

	[FW_ATTR_DST_IP] = {

		.type = NLA_U32,
	},

	[FW_ATTR_SRC_PORT] = {

		.type = NLA_U16,
	},

	[FW_ATTR_DST_PORT] = {

		.type = NLA_U16,
	},

	[FW_ATTR_PROTOCOL] = {

		.type = NLA_U8,
	},

	[FW_ATTR_ACTION] = {

		.type = NLA_U8,
	},
};

static int fw_add_rule_handler(struct sk_buff *skb, struct genl_info *info){

	struct fw_rule rule = {};

	if(info->attrs[FW_ATTR_SRC_IP])
		rule.src_ip = nla_get_u32(info->attrs[FW_ATTR_SRC_IP]);

	if(info->attrs[FW_ATTR_DST_IP])
		rule.dst_ip = nla_get_u32(info->attrs[FW_ATTR_DST_IP]);

	if(info->attrs[FW_ATTR_SRC_PORT])
		rule.src_port = nla_get_u16(info->attrs[FW_ATTR_SRC_PORT]);

	if(info->attrs[FW_ATTR_DST_PORT])
		rule.dst_port = nla_get_u16(info->attrs[FW_ATTR_DST_PORT]);

	if(info->attrs[FW_ATTR_PROTOCOL])
		rule.protocol = nla_get_u8(info->attrs[FW_ATTR_PROTOCOL]);

	if(info->attrs[FW_ATTR_ACTION])
		rule.action = nla_get_u8(info->attrs[FW_ATTR_ACTION]);

	return fw_add_rule(&rule);
};

static int fw_delete_rule_handler(struct sk_buff *skb, struct genl_info *info){

	struct fw_rule rule = {};

	if(info->attrs[FW_ATTR_SRC_IP])
		rule.src_ip = nla_get_u32(info->attrs[FW_ATTR_SRC_IP]);

	if(info->attrs[FW_ATTR_DST_IP])
		rule.dst_ip = nla_get_u32(info->attrs[FW_ATTR_DST_IP]);

	if(info->attrs[FW_ATTR_SRC_PORT])
		rule.src_port = nla_get_u16(info->attrs[FW_ATTR_SRC_PORT]);

	if(info->attrs[FW_ATTR_DST_PORT])
		rule.dst_port = nla_get_u16(info->attrs[FW_ATTR_DST_PORT]);

	if(info->attrs[FW_ATTR_PROTOCOL])
		rule.protocol = nla_get_u8(info->attrs[FW_ATTR_PROTOCOL]);

	if(info->attrs[FW_ATTR_ACTION])
		rule.action = nla_get_u8(info->attrs[FW_ATTR_ACTION]);

	return fw_delete_rule(&rule);
};

static int fw_update_rule_handler(struct sk_buff *skb, struct genl_info *info){

	struct fw_rule rule = {};

	if(info->attrs[FW_ATTR_SRC_IP])
		rule.src_ip = nla_get_u32(info->attrs[FW_ATTR_SRC_IP]);

	if(info->attrs[FW_ATTR_DST_IP])
		rule.dst_ip = nla_get_u32(info->attrs[FW_ATTR_DST_IP]);

	if(info->attrs[FW_ATTR_SRC_PORT])
		rule.src_port = nla_get_u16(info->attrs[FW_ATTR_SRC_PORT]);

	if(info->attrs[FW_ATTR_DST_PORT])
		rule.dst_port = nla_get_u16(info->attrs[FW_ATTR_DST_PORT]);

	if(info->attrs[FW_ATTR_PROTOCOL])
		rule.protocol = nla_get_u8(info->attrs[FW_ATTR_PROTOCOL]);

	if(info->attrs[FW_ATTR_ACTION])
		rule.action = nla_get_u8(info->attrs[FW_ATTR_ACTION]);

	return fw_update_rule(&rule);
};

static const struct genl_ops fw_genl_ops[] = {
	{
		.cmd = FW_CMD_ADD_RULE,
		.doit = fw_add_rule_handler,
		.policy = fw_policy,
	},
	{
		.cmd = FW_CMD_DELETE_RULE,
		.doit = fw_delete_rule_handler,
		.policy = fw_policy,
	},
	{
		.cmd = FW_CMD_UPDATE_RULE,
		.doit = fw_update_rule_handler,
		.policy = fw_policy,
	}
};

static struct genl_family fw_genl_family = {

	.name = "FWCTL",
	.version = 1,
	.maxattr = FW_ATTR_MAX,

	.ops = fw_genl_ops,
	.n_ops = ARRAY_SIZE(fw_genl_ops),
};

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

	genl_register_family(&fw_genl_family);

	pr_info("Firewall Generic Netlink family registered.\n");

	return 0;
}

static void __exit nf_logIPpacket_exit(void){

	if(nf_logIPpacket_ops != NULL){
		nf_unregister_net_hook(&init_net, nf_logIPpacket_ops);
		kfree(nf_logIPpacket_ops);
	}

	genl_unregister_family(&fw_genl_family);

	printk(KERN_INFO "The module is released.");
}

module_init(nf_logIPpacket_init);
module_exit(nf_logIPpacket_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samar");
MODULE_DESCRIPTION("Firewall using Netfilter");
MODULE_VERSION("1.0");


