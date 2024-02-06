#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "parse_app_proto.h"
#include "flow_table.h"

// mapping of control connections and data connections
ctr_to_data_conn g_ftp_ctr_to_data_conn = {0};

// ftp control connection
int parse_ftp_control_proto_info(uint8_t *payload, ftp_cdr *ftp_info, five_tuple *tuple) {
	char *save_ptr = NULL;
	char *token = NULL;
	if (NULL == payload || NULL == ftp_info) {
		printf("[%s][%s][line %d] payload or ftp_info is invalid!\n",__FILE__,__func__,__LINE__);
		return -1;
	}
	// parse payload
	if (0 == strncmp(payload, "USER", 4)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->user, save_ptr, strlen(save_ptr) - 2);
		// update five tuple of the ftp control connection
		memcpy(&g_ftp_ctr_to_data_conn.tuple, tuple, sizeof(five_tuple));
	} else if (0 == strncmp(payload, "PASS", 4)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->password, save_ptr, strlen(save_ptr) - 2);
	} else if (0 == strncmp(payload, "227 Entering Passive Mode", 25)) {    // response of PASV
		uint16_t port = 0;
		uint8_t high = 0;
		uint8_t low = 0;
		uint8_t comma_cnt = 0;
		token = strtok_r(payload, ",", &save_ptr);
		while(NULL != token) {
			comma_cnt++;
			if (5 == comma_cnt) {
				break;
			}
			token = strtok_r(NULL, ",", &save_ptr);
		}
		high = atoi(token);
		low = atoi(save_ptr);
		port = (high << 8) + low;
		ftp_info->srv_port = port;
		g_ftp_ctr_to_data_conn.srv_port = port;
	} else if (0 == strncmp(payload, "PORT", 4)) {  
		uint16_t port = 0;
		uint8_t high = 0;
		uint8_t low = 0;
		uint8_t comma_cnt = 0;
		token = strtok_r(payload, ",", &save_ptr);
		while(NULL != token) {
			comma_cnt++;
			if (5 == comma_cnt) {
				break;
			}
			token = strtok_r(NULL, ",", &save_ptr);
		}
		high = atoi(token);
		low = atoi(save_ptr);
		port = (high << 8) + low;
		ftp_info->cli_port = port;
		ftp_info->srv_port = 20;
		g_ftp_ctr_to_data_conn.srv_port = 20;
	} else if (0 == strncmp(payload, "STOR", 4)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->operation, token, strlen(token));
		memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
	} else if (0 == strncmp(payload, "RETR", 4)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->operation, token, strlen(token));
		memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
	} else if(0 == strncmp(payload, "LIST", 4)) {
        // payload split by " "
        token = strtok_r(payload, " ", &save_ptr);
        if (NULL != save_ptr && strlen(save_ptr) > 2 ){
			memcpy(ftp_info->operation, token, strlen(token));
            memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
        } else {
			memcpy(ftp_info->operation, payload, strlen(payload) - 2);
            memset(ftp_info->path, 0, FTP_PATH_SIZE);
        }
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
    } else if(0 == strncmp(payload, "NLST", 4)) {
		// payload split by " "
        token = strtok_r(payload, " ", &save_ptr);
        if (NULL != save_ptr && strlen(save_ptr) > 2) {
			memcpy(ftp_info->operation, token, strlen(token));
            memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
        } else {
			memcpy(ftp_info->operation, payload, strlen(payload) - 2);
            memset(ftp_info->path, 0, FTP_PATH_SIZE);
        }
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
    } else if (0 == strncmp(payload, "DELE", 4)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->operation, token, strlen(token));
		memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
	} else if (0 == strncmp(payload, "RMD", 3)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->operation, token, strlen(token));
		memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
	} else if (0 == strncmp(payload, "MKD", 3)) {
		// payload split by " "
		token = strtok_r(payload, " ", &save_ptr);
		memcpy(ftp_info->operation, token, strlen(token));
		memcpy(ftp_info->path, save_ptr, strlen(save_ptr) - 2);
		memset(ftp_info->file_size, 0, FTP_FILE_SIZE);
	} else if (0 == strncmp(payload, "150 Opening BINARY mode data connection for ", 44)) { // response of RETR
		token = strchr(payload, '(');
		token++;
		memcpy(ftp_info->file_size, token, strlen(token) - 4);
	} else if (0 == strncmp(payload, "QUIT", 4)) {
		// clean mapping of control connections and data connections
		memset(&g_ftp_ctr_to_data_conn, 0, sizeof(g_ftp_ctr_to_data_conn));
	}
	return 0;
}

// return 0 not ftp-data payload
// return 1 ftp-data payload
int is_ftp_data_payload(cdr *cdr_info) {
	// exist control connection
	if (exist_key_flow_table(g_flow_tbl[rte_lcore_id()], &g_ftp_ctr_to_data_conn.tuple) >= 0) {
		if(cdr_info->tuple.src_port == g_ftp_ctr_to_data_conn.srv_port || 
		   cdr_info->tuple.dst_port == g_ftp_ctr_to_data_conn.srv_port ) {
			return 1;
		}
	}
	return 0;
}

// ftp data connection
int parse_ftp_data_proto_info(uint8_t *payload, ftp_cdr *ftp_info) {
	cdr *cdr_info = NULL;

	if (NULL == payload || NULL == ftp_info) {
		printf("[%s][%s][line %d] payload or ftp_info is invalid!\n",__FILE__,__func__,__LINE__);
		return -1;
	}

	// get control info
	if (0 == ftp_info->flag) {
		if (query_flow_table(g_flow_tbl[rte_lcore_id()], &g_ftp_ctr_to_data_conn.tuple, (void **)&cdr_info) > 0) {
			memcpy(ftp_info->user, cdr_info->ftp_info.user, strlen(cdr_info->ftp_info.user));
			memcpy(ftp_info->password, cdr_info->ftp_info.password, strlen(cdr_info->ftp_info.password));
			memcpy(ftp_info->operation, cdr_info->ftp_info.operation, strlen(cdr_info->ftp_info.operation));
			memcpy(ftp_info->path, cdr_info->ftp_info.path, strlen(cdr_info->ftp_info.path));
			memcpy(ftp_info->file_size, cdr_info->ftp_info.file_size, strlen(cdr_info->ftp_info.file_size));
			ftp_info->flag = 1;
		}
	}
	
	/* to do file reassembly */

	return 0;
}



const char *http_signature[] = {
	"DUMMY",
	"HTTP/",
	"GET",
	"POST",
	"PUT",
	"DELETE",
	"HEAD",
	"OPTIONS",
	"TRACE",
	"CONNECT",
	"PATCH",
	NULL,
};
// same prefix with longer prefix before
const char *http_field_name[] = {    
    "Accept-Encoding",
	"Accept-Language",
	"Accept-Charset",
	"Accept-Ranges",
	"Accept",
	"Content-Type",
	"Content-Length",
	"Connection",
	"Host",
	"User-Agent",
	"Authenticate",
	"Date",
	NULL,
};

// return 0 not http payload
// return 1 http response
// return 2-10 http request method
int is_http_payload(uint8_t *payload) {
	int i = 0;
	for ( i = 1; http_signature[i] != NULL ; i++) {
		if (strncmp(payload, http_signature[i], strlen(http_signature[i])) == 0) {
			return i;
		}
	}
	return 0;
}

int parse_http_proto_info(uint8_t *payload, http_cdr *http_info, int op) {
	char *lines[32] = {NULL};  
    int line_cnt = 0;
	char *save_ptr = NULL;
	char *token = NULL;
	int i = 0;
	int j = 0;
  
	if (NULL == payload || NULL == http_info) {
		printf("[%s][%s][line %d] payload or http_info is invalid!\n",__FILE__,__func__,__LINE__);
		return -1;
	}

    // payload split by \r\n
	lines[line_cnt] = strtok_r(payload, "\r\n", &save_ptr);
    while (lines[line_cnt] != NULL && line_cnt < 32) {
		if (strncmp(save_ptr, "\n\r\n", 3) == 0) {    // start line and header line are the end
			break;
		}
		line_cnt++;
		lines[line_cnt] = strtok_r(NULL, "\r\n", &save_ptr);
    }

	// parse each line
	while (lines[i] != NULL)
	{	
		if(0 == i) {          // start line
			if (1 == op) {    // status line
				token = strtok_r(lines[i], " ", &save_ptr);
				memcpy(http_info->status_line.version, token, strlen(token));
				token = strtok_r(NULL, "\r\n", &save_ptr);
				memcpy(http_info->status_line.status, token, strlen(token));
			} else {          // request line
				memcpy(http_info->request_line.method, http_signature[op], strlen(http_signature[op]));
				token = strtok_r(lines[i], " ", &save_ptr);
				token = strtok_r(NULL, " ", &save_ptr);
				memcpy(http_info->request_line.url, token, strlen(token));
				token = strtok_r(NULL, "\r\n", &save_ptr);
				memcpy(http_info->request_line.version, token, strlen(token));
			}
		} else {              // field line
			if (1== op) {     // response field
				for (j = 0; http_field_name[j] != NULL ; j++) {
					if (strncmp(lines[i], http_field_name[j], strlen(http_field_name[j])) == 0) {
						memcpy(http_info->resp_hdr.fields[http_info->resp_hdr.field_num].field_name, http_field_name[j], strlen(http_field_name[j]));
						http_info->resp_hdr.fields[http_info->resp_hdr.field_num].field_name_len = strlen(http_field_name[j]);
						token = strtok_r(lines[i], ":", &save_ptr);
						memcpy(http_info->resp_hdr.fields[http_info->resp_hdr.field_num].field_value, save_ptr, strlen(save_ptr));
						http_info->resp_hdr.fields[http_info->resp_hdr.field_num].field_value_len = strlen(save_ptr);
						http_info->resp_hdr.field_num++;
						break;
					}
				}
			} else {          // request field
				for (j = 0; http_field_name[j] != NULL ; j++) {
					if (strncmp(lines[i], http_field_name[j], strlen(http_field_name[j])) == 0) {
						memcpy(http_info->req_hdr.fields[http_info->req_hdr.field_num].field_name, http_field_name[j], strlen(http_field_name[j]));
						http_info->req_hdr.fields[http_info->req_hdr.field_num].field_name_len = strlen(http_field_name[j]);
						token = strtok_r(lines[i], ":", &save_ptr);
						memcpy(http_info->req_hdr.fields[http_info->req_hdr.field_num].field_value, save_ptr, strlen(save_ptr));
						http_info->req_hdr.fields[http_info->req_hdr.field_num].field_value_len = strlen(save_ptr);
						http_info->req_hdr.field_num++;
						break;
					}
				}
			}
		}
		i++;
	}
	return 0;
}

int parse_app_proto_info(uint8_t *payload, cdr *cdr_info) {
	int op = 0;    // request or response
	if (NULL == payload || NULL == cdr_info) {
		printf("[%s][%s][line %d] payload or cdr_info is invalid!\n",__FILE__,__func__,__LINE__);
		return -1;
	}

	op = is_http_payload(payload);
	if (is_http_payload(payload)) { // http protocol
		cdr_info->app_proto_type = PROTO_HTTP;
		//printf("payload %s!\n",payload);
		return parse_http_proto_info(payload, &cdr_info->http_info, op);
	} else if (cdr_info->tuple.src_port == 21 || cdr_info->tuple.dst_port == 21) {    // ftp control connection
		//printf("payload: %s!\n", payload);
		cdr_info->app_proto_type = PROTO_FTP_CTR;
		return parse_ftp_control_proto_info(payload, &cdr_info->ftp_info, &cdr_info->tuple);
	} else if (is_ftp_data_payload(cdr_info)) {    // ftp data connection
		cdr_info->app_proto_type = PROTO_FTP_DATA;
		return parse_ftp_data_proto_info(payload, &cdr_info->ftp_info);
	} else {
		//cdr_info->app_proto_type = PROTO_UNKNOWN;
		printf("[%s][%s][line %d] unknow application protocol!\n",__FILE__,__func__,__LINE__);
		return -1;
	}
	return 0;
}