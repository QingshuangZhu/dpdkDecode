#include <time.h>

#include <rte_malloc.h>

#include "flow_table.h"
#include "parse_l2_to_l4_proto.h"
#include "parse_app_proto.h"

// golbal flow table
struct rte_hash *g_flow_tbl[32] = {NULL};    // key is five tuple, value is cdr

int insert_flow_table(const struct rte_hash *flow_tbl, const void *flow_key, void **flow_data)
{
	five_tuple tuple = {0};
	int ret = 0;
    if(unlikely(NULL == flow_tbl || NULL == flow_key || NULL == flow_data))
    {
        printf("[%s][%s][line %d] input parameter flow_tbl or flow_key or flow_data is NULL!\n",__FILE__,__func__,__LINE__);
        return -1;
    }

	ret = rte_hash_lookup_data(flow_tbl, flow_key, flow_data);
	if(unlikely(-ENOENT == ret)) {
		// swap five tuple Direction and look up again
		tuple.ip_ver = ((five_tuple *) flow_key)->ip_ver;
		if (IP_VER_IPV4 == ((five_tuple *) flow_key)->ip_ver) {
			tuple.ipv4.src_addr = ((five_tuple *) flow_key)->ipv4.dst_addr;
			tuple.ipv4.dst_addr = ((five_tuple *) flow_key)->ipv4.src_addr;
		} else {
			memcpy(&tuple.ipv6.src_addr, &((five_tuple *) flow_key)->ipv6.dst_addr, sizeof(tuple.ipv6.src_addr));
			memcpy(&tuple.ipv6.dst_addr, &((five_tuple *) flow_key)->ipv6.src_addr, sizeof(tuple.ipv6.dst_addr));
		}
		tuple.src_port = ((five_tuple *) flow_key)->dst_port;
		tuple.dst_port = ((five_tuple *) flow_key)->src_port;
		tuple.proto_type = ((five_tuple *) flow_key)->proto_type;
		ret = rte_hash_lookup_data(flow_tbl, &tuple, flow_data);
		if(unlikely(-ENOENT == ret)) {
			*flow_data = rte_zmalloc_socket("cdr", sizeof(cdr), RTE_CACHE_LINE_SIZE, rte_socket_id());
            if(unlikely(NULL == *flow_data))
            {
                printf("[%s][%s][line %d] flow data allocation failed!\n",__FILE__,__func__,__LINE__);
                return -1;
            }
			memcpy(*flow_data, flow_key, sizeof(five_tuple));
			// create flow timestamp
			clock_gettime(CLOCK_REALTIME, &((cdr *)*flow_data)->timestamp);
			return rte_hash_add_key_data(flow_tbl, flow_key, *flow_data);
		}
	}
	// update flow timestamp
	if (NULL != *flow_data) {
		clock_gettime(CLOCK_REALTIME, &((cdr *)*flow_data)->timestamp);
	}
    return ret;
}

int delete_flow_table(const struct rte_hash *flow_tbl, const void *flow_key)
{
	five_tuple tuple = {0};
	int ret = 0;
    if(unlikely(NULL == flow_tbl || NULL == flow_key))
    {
        printf("[%s][%s][line %d] input parameter flow_tbl or flow_key is NULL!\n",__FILE__,__func__,__LINE__);
        return -1;
    }
	ret = rte_hash_del_key(flow_tbl, flow_key);
	if(unlikely(-ENOENT == ret))
	{
		// swap five tuple Direction and delete again
		tuple.ip_ver = ((five_tuple *) flow_key)->ip_ver;
		if (IP_VER_IPV4 == ((five_tuple *) flow_key)->ip_ver) {
			tuple.ipv4.src_addr = ((five_tuple *) flow_key)->ipv4.dst_addr;
			tuple.ipv4.dst_addr = ((five_tuple *) flow_key)->ipv4.src_addr;
		} else {
			memcpy(&tuple.ipv6.src_addr, &((five_tuple *) flow_key)->ipv6.dst_addr, sizeof(tuple.ipv6.src_addr));
			memcpy(&tuple.ipv6.dst_addr, &((five_tuple *) flow_key)->ipv6.src_addr, sizeof(tuple.ipv6.dst_addr));
		}
		tuple.src_port = ((five_tuple *) flow_key)->dst_port;
		tuple.dst_port = ((five_tuple *) flow_key)->src_port;
		tuple.proto_type = ((five_tuple *) flow_key)->proto_type;
		ret = rte_hash_del_key(flow_tbl, &tuple);
	}
	return ret;
}

int update_flow_table(const struct rte_hash *flow_tbl, const void *flow_key, void *flow_data)
{
	five_tuple tuple = {0};
	int ret = 0;
    if(unlikely(NULL == flow_tbl || NULL == flow_key || NULL == flow_data))
    {
        printf("[%s][%s][line %d] input parameter flow_tbl or flow_key or flow_data is NULL!\n",__FILE__,__func__,__LINE__);
        return -1;
    }

	ret = rte_hash_lookup(flow_tbl, flow_key);
	if(unlikely(-ENOENT == ret)) {
		// swap five tuple Direction and look up again
		tuple.ip_ver = ((five_tuple *) flow_key)->ip_ver;
		if (IP_VER_IPV4 == ((five_tuple *) flow_key)->ip_ver) {
			tuple.ipv4.src_addr = ((five_tuple *) flow_key)->ipv4.dst_addr;
			tuple.ipv4.dst_addr = ((five_tuple *) flow_key)->ipv4.src_addr;
		} else {
			memcpy(&tuple.ipv6.src_addr, &((five_tuple *) flow_key)->ipv6.dst_addr, sizeof(tuple.ipv6.src_addr));
			memcpy(&tuple.ipv6.dst_addr, &((five_tuple *) flow_key)->ipv6.src_addr, sizeof(tuple.ipv6.dst_addr));
		}
		tuple.src_port = ((five_tuple *) flow_key)->dst_port;
		tuple.dst_port = ((five_tuple *) flow_key)->src_port;
		tuple.proto_type = ((five_tuple *) flow_key)->proto_type;
		ret = rte_hash_lookup(flow_tbl, &tuple);
		if(unlikely(-ENOENT == ret)) {
			return ret;
		}
		return rte_hash_add_key_data(flow_tbl, &tuple, flow_data);
	}
    return rte_hash_add_key_data(flow_tbl, flow_key, flow_data);
}

int query_flow_table(const struct rte_hash *flow_tbl, const void *flow_key, void **flow_data)
{
	five_tuple tuple = {0};
	int ret = 0;
    if(unlikely(NULL == flow_tbl || NULL == flow_key || NULL == flow_data))
    {
        printf("[%s][%s][line %d] input parameter flow_tbl or flow_key or flow_data is NULL!\n",__FILE__,__func__,__LINE__);
        return -1;
    }
	
	ret = rte_hash_lookup_data(flow_tbl, flow_key, flow_data);
	if(unlikely(-ENOENT == ret)) {
		// swap five tuple Direction and look up again
		tuple.ip_ver = ((five_tuple *) flow_key)->ip_ver;
		if (IP_VER_IPV4 == ((five_tuple *) flow_key)->ip_ver) {
			tuple.ipv4.src_addr = ((five_tuple *) flow_key)->ipv4.dst_addr;
			tuple.ipv4.dst_addr = ((five_tuple *) flow_key)->ipv4.src_addr;
		} else {
			memcpy(&tuple.ipv6.src_addr, &((five_tuple *) flow_key)->ipv6.dst_addr, sizeof(tuple.ipv6.src_addr));
			memcpy(&tuple.ipv6.dst_addr, &((five_tuple *) flow_key)->ipv6.src_addr, sizeof(tuple.ipv6.dst_addr));
		}
		tuple.src_port = ((five_tuple *) flow_key)->dst_port;
		tuple.dst_port = ((five_tuple *) flow_key)->src_port;
		tuple.proto_type = ((five_tuple *) flow_key)->proto_type;
		ret = rte_hash_lookup_data(flow_tbl, &tuple, flow_data);
	}
    return ret;
}


// whether the key exists
int exist_key_flow_table(const struct rte_hash *flow_tbl, const void *flow_key)
{
	five_tuple tuple = {0};
	int ret = 0;
    if(unlikely(NULL == flow_tbl || NULL == flow_key ))
    {
        printf("[%s][%s][line %d] input parameter flow_tbl or flow_key is NULL!\n",__FILE__,__func__,__LINE__);
        return -1;
    }
	
	ret = rte_hash_lookup(flow_tbl, flow_key);
	if(unlikely(-ENOENT == ret)) {
		// swap five tuple Direction and look up again
		tuple.ip_ver = ((five_tuple *) flow_key)->ip_ver;
		if (IP_VER_IPV4 == ((five_tuple *) flow_key)->ip_ver) {
			tuple.ipv4.src_addr = ((five_tuple *) flow_key)->ipv4.dst_addr;
			tuple.ipv4.dst_addr = ((five_tuple *) flow_key)->ipv4.src_addr;
		} else {
			memcpy(&tuple.ipv6.src_addr, &((five_tuple *) flow_key)->ipv6.dst_addr, sizeof(tuple.ipv6.src_addr));
			memcpy(&tuple.ipv6.dst_addr, &((five_tuple *) flow_key)->ipv6.src_addr, sizeof(tuple.ipv6.dst_addr));
		}
		tuple.src_port = ((five_tuple *) flow_key)->dst_port;
		tuple.dst_port = ((five_tuple *) flow_key)->src_port;
		tuple.proto_type = ((five_tuple *) flow_key)->proto_type;
		ret = rte_hash_lookup(flow_tbl, &tuple);
	}
    return ret;
}
