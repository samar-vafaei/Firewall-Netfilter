#include "rule_engine.h"


static struct fw_rule_table fw_table;


// private helper
static bool rules_equal (const struct fw_rule* r1, const struct fw_rule* r2){

	return r1->protocol==r2->protocol &&
	       r1->src_ip==r2->src_ip &&
	       r1->dst_ip==r2->dst_ip &&
	       r1->src_port==r2->src_port &&
	       r1->dst_port==r2->dst_port &&
	       r1->action==r2->action;
};

static struct fw_rule* find_rule (const struct fw_rule* rule){

	struct fw_rule* tmp;

	list_for_each_entry(tmp,&fw_table.head,node){

		if(rules_equal(rule,tmp))
			return tmp;	
	}

	return NULL;
};

static void copy_rule(struct fw_rule* r1,const struct fw_rule* r2){

	r1->protocol = r2->protocol;
	r1->src_ip = r2->src_ip;
	r1->dst_ip = r2->dst_ip;
	r1->src_port = r2->src_port;
	r1->dst_port = r2->dst_port;
	r1->action = r2->action;
};


void fw_rule_engine_init(void){

	pr_info("*** Initialize the rule engine ***\n");

	INIT_LIST_HEAD(&fw_table.head);
	fw_table.count = 0;
};

void fw_rule_engine_exit(void){

	pr_info("*** Exit the rule engine ***\n");
};


// public API
enum fw_result fw_add_rule(const struct fw_rule *rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;
	found = find_rule(rule);

	if(!found)
		return FW_ERR_RULE_NOT_FOUND;

	struct fw_rule *new_rule;
	new_rule = kmalloc(sizeof(struct fw_rule),GFP_KERNEL);

	if(!new_rule)
		return FW_ERR_NO_MEMORY;

	copy_rule(new_rule,rule);

	INIT_LIST_HEAD(&new_rule->node);

	list_add_tail(&new_rule->node,&fw_table.head);

	fw_table.count++;

	return FW_OK;
};

enum fw_result fw_delete_rule(const struct fw_rule *rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;
	found = find_rule(rule);

	if(!found)
		return FW_ERR_RULE_NOT_FOUND;

	list_del(&found->node);
	kfree(found);

	fw_table.count--;

	return FW_OK;
};

enum fw_result fw_flush_rule(void){

	struct fw_rule *rule;
	struct fw_rule *tmp;

	list_for_each_entry_safe(rule,tmp,&fw_table.head,node){

		list_del(&rule->node);
		kfree(rule);
	}

	return FW_OK;
};

enum fw_result fw_update_rule(const struct fw_rule* rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;
	found = find_rule(rule);

	if(!found)
		return FW_ERR_RULE_NOT_FOUND;

	copy_rule(found,rule);

	return FW_OK;
};

static struct fw_rule* fw_find_matching_rule(const struct packet_info* pkt){

	struct fw_rule *rule;

	list_for_each_entry(rule,&fw_table.head,node){

		if(rule->protocol != pkt->protocol)
			continue;

		if(rule->src_ip != pkt->src_ip)
			continue;

		if(rule->dst_ip != pkt->dst_ip)
			continue;

		if(rule->src_port != pkt->src_port)
			continue;

		if(rule->dst_port != pkt->dst_port)
			continue;

		return rule;
	}

	return NULL;
}

enum fw_action fw_match_packet(const struct packet_info* pkt){

	struct fw_rule *rule;

	rule = fw_find_matching_rule(pkt);

	if(!rule)
		return FW_ACCEPT;

	return rule->action;
}
