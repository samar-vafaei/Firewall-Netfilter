#include "rule_engine.h"


static struct fw_rule_table fw_table;


// Private helper
typedef bool (*fw_rules_equal_fp)(const struct fw_rule* rule,
					enum context_type type,
					const void* context);

static void fw_rule_free_rcu(struct rcu_head *rcu);
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
			       rule->dst_port==input->dst_port; //&&
			       //rule->action==input->action;

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

	list_for_each_entry_rcu(rule,&fw_table.head,node){

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

static void fw_rule_free_rcu(struct rcu_head *rcu){

	struct fw_rule *rule;

	rule = container_of(rcu, struct fw_rule, rcu);

	kfree(rule);
};


void fw_rule_engine_init(void){

	pr_info("*** Initialize the rule engine ***\n");

	INIT_LIST_HEAD(&fw_table.head);
	mutex_init(&fw_table.lock);
	fw_table.count = 0;
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
	new_rule = kzalloc(sizeof(struct fw_rule),GFP_KERNEL);

	if(!new_rule)
		return FW_ERR_NO_MEMORY;

	fw_copy_rule(new_rule,rule);

	INIT_LIST_HEAD(&new_rule->node);

	struct fw_rule *found;

	mutex_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule);

	if(found){
		mutex_unlock(&fw_table.lock);
		kfree(new_rule);
		return FW_ERR_RULE_EXISTS;
	}

	list_add_tail_rcu(&new_rule->node,&fw_table.head);
	fw_table.count++;

	mutex_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_result fw_delete_rule(const struct fw_rule *rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;

	mutex_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule);

	if(!found){
		mutex_unlock(&fw_table.lock);
		return FW_ERR_RULE_NOT_FOUND;
	}

	list_del_rcu(&found->node);

	fw_table.count--;

	mutex_unlock(&fw_table.lock);

	call_rcu(&found->rcu,fw_rule_free_rcu);

	return FW_OK;
};

enum fw_result fw_flush_rule(void){

	struct fw_rule *rule;
	struct fw_rule *tmp;

	mutex_lock(&fw_table.lock);

	list_for_each_entry_safe(rule,tmp,&fw_table.head,node){

		list_del_rcu(&rule->node);
		call_rcu(&rule->rcu,fw_rule_free_rcu);
	}

	fw_table.count = 0;

	mutex_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_result fw_update_rule(const struct fw_rule* rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *new_rule;
	new_rule = kzalloc(sizeof(struct fw_rule),GFP_KERNEL);

	if(!new_rule)
		return FW_ERR_NO_MEMORY;

	INIT_LIST_HEAD(&new_rule->node);

	fw_copy_rule(new_rule,rule);

	struct fw_rule *found;

	mutex_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule);

	if(!found){
		mutex_unlock(&fw_table.lock);
		kfree(new_rule);
		return FW_ERR_RULE_NOT_FOUND;
	}

	list_replace_rcu(&found->node, &new_rule->node);

	mutex_unlock(&fw_table.lock);

	call_rcu(&found->rcu,fw_rule_free_rcu);

	return FW_OK;
};

enum fw_action fw_match_packet(const struct packet_info* pkt){

	if(!pkt)
		return FW_ACCEPT;

	struct fw_rule *rule;
	enum fw_action action;

	rcu_read_lock();

	rule = fw_find_rule(fw_rules_equal,CTX_PACKET,pkt);

	if(!rule)
		action = FW_ACCEPT;

	else 
	       action =	rule->action;

	rcu_read_unlock();

	return action;
};
