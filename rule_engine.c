#include "rule_engine.h"


static struct fw_rule_table fw_table;


// Private helper
typedef bool (*fw_rules_equal_fp)(const struct fw_rule* rule,
					enum context_type type,
					const void* context);

static void fw_rule_table_init(void);
static void fw_rule_free_rcu(struct rcu_head *rcu);
static bool fw_rules_equal (const struct fw_rule* rule, enum context_type type, const void* context);
static struct fw_rule* fw_find_rule(fw_rules_equal_fp fw_matcher, enum context_type type, const void* context, const unsigned int idx);
static void fw_copy_rule(struct fw_rule* r1,const struct fw_rule* r2);
static struct fw_hash_key* fw_hash_table_key_rule(const struct fw_rule *rule);
static struct fw_hash_key* fw_hash_table_key_pkt(const struct packet_info *pkt);
static unsigned int fw_hash_table_bucket_index(const struct fw_hash_key *key);


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

static struct fw_rule* fw_find_rule(fw_rules_equal_fp fw_matcher, enum context_type type, const void* context, const unsigned int idx){

	struct fw_rule *rule;

        hlist_for_each_entry_rcu(rule,&fw_table.buckets[idx],hnode){

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

static void fw_rule_table_init(void){

	unsigned int i;

	mutex_init(&fw_table.lock);

	for(i=0; i<FW_HASH_SIZE; i++){

		INIT_HLIST_HEAD(&fw_table.buckets[i]);
	}

	fw_table.count = 0;
}

static struct fw_hash_key* fw_hash_table_key_rule(const struct fw_rule *rule){

	struct fw_hash_key *key;
	key = kzalloc(sizeof(struct fw_hash_key),GFP_KERNEL);

	if(!key)
		return NULL;

	key->protocol = rule->protocol;
	key->src_ip = rule->src_ip;
	key->dst_ip = rule->dst_ip;
	key->src_port = rule->src_port;
	key->dst_port = rule->dst_port;

	return key;
}

static struct fw_hash_key* fw_hash_table_key_pkt(const struct packet_info *pkt){

	struct fw_hash_key *key;
	key = kzalloc(sizeof(struct fw_hash_key),GFP_KERNEL);

	if(!key)
		return NULL;

	key->protocol = pkt->protocol;
	key->src_ip = pkt->src_ip;
	key->dst_ip = pkt->dst_ip;
	key->src_port = pkt->src_port;
	key->dst_port = pkt->dst_port;

	return key;
}

static unsigned int fw_hash_table_bucket_index(const struct fw_hash_key *key){

	u32 hash;
	unsigned int idx;

	hash = jhash(key,sizeof(*key),0);

	idx = hash & (FW_HASH_SIZE - 1);

	return idx;
}


void fw_rule_engine_init(void){

	pr_info("*** Initialize the rule engine ***\n");

	fw_rule_table_init();
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

	INIT_HLIST_NODE(&new_rule->hnode);

	struct fw_rule *found;
	unsigned int idx;
	struct fw_hash_key *key;

	key = fw_hash_table_key_rule(new_rule);

	idx = fw_hash_table_bucket_index(key);

	mutex_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,new_rule,idx);

	if(found){
		mutex_unlock(&fw_table.lock);
		kfree(new_rule);
		return FW_ERR_RULE_EXISTS;
	}

	hlist_add_head_rcu(&new_rule->hnode,&fw_table.buckets[idx]);
	fw_table.count++;

	mutex_unlock(&fw_table.lock);

	return FW_OK;
};

enum fw_result fw_delete_rule(const struct fw_rule *rule){

	if(!rule)
		return FW_ERR_INVALID_ARGUMENT;

	struct fw_rule *found;
	unsigned int idx;
	struct fw_hash_key *key;

	key = fw_hash_table_key_rule(rule);

	idx = fw_hash_table_bucket_index(key);

	mutex_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,rule,idx);

	if(!found){
		mutex_unlock(&fw_table.lock);
		return FW_ERR_RULE_NOT_FOUND;
	}

	hlist_del_rcu(&found->hnode);

	fw_table.count--;

	mutex_unlock(&fw_table.lock);

	call_rcu(&found->rcu,fw_rule_free_rcu);

	return FW_OK;
};

enum fw_result fw_flush_rule(void){

	struct fw_rule *rule;
	struct hlist_node *tmp;

	mutex_lock(&fw_table.lock);

	for(int idx=0;idx<FW_HASH_SIZE;idx++){

		hlist_for_each_entry_safe(rule,tmp,&fw_table.buckets[idx],hnode){

			hlist_del_rcu(&rule->hnode);
			call_rcu(&rule->rcu,fw_rule_free_rcu);
		}
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

	INIT_HLIST_NODE(&new_rule->hnode);

	fw_copy_rule(new_rule,rule);

	struct fw_rule *found;
	unsigned int idx;
	struct fw_hash_key *key;

	key = fw_hash_table_key_rule(new_rule);

	idx = fw_hash_table_bucket_index(key);

	mutex_lock(&fw_table.lock);

	found = fw_find_rule(fw_rules_equal,CTX_RULE,new_rule,idx);

	if(!found){
		mutex_unlock(&fw_table.lock);
		kfree(new_rule);
		return FW_ERR_RULE_NOT_FOUND;
	}

	hlist_replace_rcu(&found->hnode, &new_rule->hnode);

	mutex_unlock(&fw_table.lock);

	call_rcu(&found->rcu,fw_rule_free_rcu);

	return FW_OK;
};

enum fw_action fw_match_packet(const struct packet_info* pkt){

	if(!pkt)
		return FW_ACCEPT;

	struct fw_rule *rule;
	enum fw_action action;
	unsigned int idx;
	struct fw_hash_key *key;

	key = fw_hash_table_key_pkt(pkt);

	idx = fw_hash_table_bucket_index(key);

	rcu_read_lock();
 
	rule = fw_find_rule(fw_rules_equal,CTX_PACKET,pkt,idx);

	if(!rule)
		action = FW_ACCEPT;

	else 
	       action =	rule->action;

	rcu_read_unlock();

	return action;
};
