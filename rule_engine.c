#include "rule_engine.h"


static struct fw_rule_table fw_table;


// Private helper
typedef bool (*fw_rules_equal_fp)(const struct fw_rule* rule,
					enum context_type type,
					const void* context);

static bool fw_rules_equal (const struct fw_rule* rule, enum context_type type, const void* context);
static struct fw_rule* fw_find_rule(fw_rules_equal_fp fw_matcher, enum context_type type, const void* context);
static void fw_copy_rule(struct fw_rule* r1,const struct fw_rule* r2);


static bool fw_rules_equal (const struct fw_rule* rule, enum context_type type, const void* context){

	switch(type){

		case CTX_RULE:
		        // cast	
			const struct fw_rule* input = context;

			return rule->protocol==input->protocol &&
			       rule->src_ip==input->src_ip &&
			       rule->dst_ip==input->dst_ip &&
			       rule->src_port==input->src_port &&
			       rule->dst_port==input->dst_port &&
			       rule->action==input->action;

		case CTX_PACKET:
		        // cast	
			const struct packet_info* pkt = context;

			return rule->protocol==pkt->protocol &&
			       rule->src_ip==pkt->src_ip &&
			       rule->dst_ip==pkt->dst_ip &&
			       rule->src_port==pkt->src_port &&
			       rule->dst_port==pkt->dst_port;

		default:
			return false;
	}
};

static struct fw_rule* fw_find_rule(fw_rules_equal_fp fw_matcher, enum context_type type,const void* context){

	struct fw_rule *rule;

	list_for_each_entry(rule,&fw_table.head,node){

		if(fw_matcher(rule,type,context))
			return rule;	
	}

	return NULL;
}

static void fw_copy_rule(struct fw_rule* r1,const struct fw_rule* r2){

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
	//spin_lock_init(&fw_table.lock);
	rwlock_init(&fw_table.lock);
};

void fw_rule_engine_exit(void){

	pr_info("*** Exit the rule engine ***\n");

	fw_flush_rule();
};


// Public API
enum fw_result fw_add_rule(const struct fw_rule *rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *new_rule;
	//new_rule = kmalloc(sizeof(struct fw_rule),GFP_KERNEL);
	new_rule = kzalloc(sizeof(struct fw_rule),GFP_KERNEL);

	if(!new_rule)
		return FW_ERR_NO_MEMORY;

	fw_copy_rule(new_rule,rule);

	INIT_LIST_HEAD(&new_rule->node);

	struct fw_rule *found;
	//spin_lock(&fw_table.lock);
	write_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule);

	if(found){
		//spin_unlock(&fw_table.lock);
		write_unlock(&fw_table.lock);
		kfree(new_rule);
		return FW_ERR_RULE_EXISTS;
	}

	list_add_tail(&new_rule->node,&fw_table.head);
	fw_table.count++;

	//spin_unlock(&fw_table.lock);
	write_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_result fw_delete_rule(const struct fw_rule *rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;
	//spin_lock(&fw_table.lock);
	write_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule);

	if(!found){
		//spin_unlock(&fw_table.lock);
		write_unlock(&fw_table.lock);
		return FW_ERR_RULE_NOT_FOUND;
	}

	list_del(&found->node);
	kfree(found);
	fw_table.count--;

	//spin_unlock(&fw_table.lock);
	write_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_result fw_flush_rule(void){

	struct fw_rule *rule;
	struct fw_rule *tmp;
 
	//spin_lock(&fw_table.lock);
	write_lock(&fw_table.lock);

	list_for_each_entry_safe(rule,tmp,&fw_table.head,node){

		list_del(&rule->node);
		kfree(rule);
	}
	fw_table.count = 0;

	//spin_unlock(&fw_table.lock);
	write_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_result fw_update_rule(const struct fw_rule* rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;
	//spin_lock(&fw_table.lock);
	write_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule);

	if(!found){
		//spin_unlock(&fw_table.lock);
		write_unlock(&fw_table.lock);
		return FW_ERR_RULE_NOT_FOUND;
	}

	fw_copy_rule(found,rule);

	//spin_unlock(&fw_table.lock);
	write_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_action fw_match_packet(const struct packet_info* pkt){

	if(!pkt)
		return FW_ACCEPT;

	struct fw_rule *rule;
	enum fw_action action;

	//spin_lock(&fw_table.lock);
	read_lock(&fw_table.lock);

	rule = fw_find_rule(fw_rules_equal,CTX_PACKET,pkt);

	if(!rule)
		action = FW_ACCEPT;

	else 
	       action =	rule->action;

	//spin_unlock(&fw_table.lock);
	read_unlock(&fw_table.lock);

	return action;
};
