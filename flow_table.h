#ifndef FLOW_TABLE_H_
#define FLOW_TABLE_H_

#include <sys/queue.h>

#include <rte_hash.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FLOW_TABLE_AGE_SEC    60

typedef struct key_to_delete {
    TAILQ_ENTRY(key_to_delete) next;
    void *tuple;
} key_to_delete_t;

// golbal flow table
extern struct rte_hash *g_flow_tbl[32];    // key is five tuple, value is cdr

int insert_flow_table(const struct rte_hash *flow_tbl, const void *flow_key, void **flow_data);
int delete_flow_table(const struct rte_hash *flow_tbl, const void *flow_key);
int update_flow_table(const struct rte_hash *flow_tbl, const void *flow_key, void *flow_data);
int query_flow_table(const struct rte_hash *flow_tbl, const void *flow_key, void **flow_data);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_TABLE_H_ */