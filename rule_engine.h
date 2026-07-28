#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <linux/types.h>
#include <linux/list.h>

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

/* Rule + Rule Table */
struct fw_rule {

	__be32 src_ip;
	__be32 dst_ip;

	__be16 src_port;	
	__be16 dst_port;

	u8 protocol;

        enum fw_action action; 
	
	struct list_head node;
};

struct fw_rule_table {

	struct list_head head;

	//spinlock_t lock;

	unsigned int count;
};

void fw_rule_engine_init(void);
void fw_rule_engine_exit(void);

/* Rule Engine APIs called by Netlink */
/* Rule management */
static bool rules_equal (const struct fw_rule* r1, const struct fw_rule* r2);
static struct fw_rule* find_rule (const struct fw_rule* rule);
static void copy_rule(struct fw_rule* r1,const struct fw_rule* r2);

enum fw_result fw_add_rule(const struct fw_rule* rule);
enum fw_result fw_delete_rule(const struct fw_rule* rule);
enum fw_result fw_flush_rule(void);
enum fw_result fw_update_rule(const struct fw_rule* rule);

/* Lookup the rule */
static struct fw_rule* fw_find_matching_rule(const struct packet_info* pkt);
enum fw_action fw_match_packet(const struct packet_info* pkt);


#endif
