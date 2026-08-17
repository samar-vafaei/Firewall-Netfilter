#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <linux/types.h>
#include <linux/list.h>
//#include <linux/spinlock.h>

#include "packet_parser.h"


/* NF_ACCEPT NF_DROP */
enum fw_action {
	
	FW_ACCEPT,
	FW_DROP,
	FW_FORWARD
};

enum fw_result {

	FW_OK,
	FW_ERR_INVALID_ARGUMENT,
	FW_ERR_NO_MEMORY,
	FW_ERR_RULE_EXISTS,
	FW_ERR_RULE_NOT_FOUND,
	FW_ERR_TABLE_FULL,
	FW_ERR_INTERNAL
};

enum context_type {

	CTX_RULE,
	CTX_PACKET
};

/* Rule + Rule Table */
struct fw_rule {

	__be32 src_ip;
	__be32 dst_ip;

	__be16 src_port;	
	__be16 dst_port;

	u8 protocol;

        enum fw_action action; 
	
	struct list_head node;

	struct rcu_head rcu;
};

struct fw_rule_table {

	struct list_head head;

	struct mutex lock;

	unsigned int count;
};

void fw_rule_engine_init(void);
void fw_rule_engine_exit(void);

/* Rule Engine APIs called by Netlink */
/* Rule management */
enum fw_result fw_add_rule(const struct fw_rule* rule);
enum fw_result fw_delete_rule(const struct fw_rule* rule);
enum fw_result fw_flush_rule(void);
enum fw_result fw_update_rule(const struct fw_rule* rule);

/* Lookup the rule */
enum fw_action fw_match_packet(const struct packet_info* pkt);


#endif
