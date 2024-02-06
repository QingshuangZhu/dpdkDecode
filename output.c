#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "output.h"

const char *cdr_http_req_fields[] = {
	"Accept-Language",
	"Accept-Encoding",
	"Accept-Charset", 
	"Accept", 
	"Content-Type",
	"Content-Length",
	"Connection", 
	"User-Agent", 
	"Host",
	NULL,
};

const char *cdr_http_resp_fields[] = {
	"Content-Type",
	"Content-Length",
	"Date", 
	NULL,
};

int cdr_output(cdr *cdr_info) {
	FILE *fp = NULL;
	char src_ip[46] = {0};
    char dst_ip[46] = {0};
	struct protoent *proto = NULL;
	int i = 0;
	int j = 0;
	int exist = 0;

	proto = getprotobynumber(cdr_info->tuple.proto_type);
	if (IP_VER_IPV4 == cdr_info->tuple.ip_ver) {
		inet_ntop(AF_INET, &cdr_info->tuple.ipv4.src_addr, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, &cdr_info->tuple.ipv4.dst_addr, dst_ip, sizeof(dst_ip));
	} else {
		inet_ntop(AF_INET6, &cdr_info->tuple.ipv6.src_addr, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET6, &cdr_info->tuple.ipv6.dst_addr, dst_ip, sizeof(dst_ip));
	}

	if (cdr_info->app_proto_type == PROTO_HTTP) {
		char *file_name = "http_cdr.csv";
		// file doesn’t exist
		if (-1 == access(file_name, F_OK)) {
			printf("http_cdr.csv file doesn't exist\n");
			fp = fopen(file_name, "a"); 
			if (fp == NULL) {  
				printf("can not open the file:%s\n", file_name);  
				return -1;  
			}
			// write table header to file
			fprintf(fp, "src_add\t dst_add\t transport_layer_proto\t  src_port\t dst_port\t app_proto_type\t \
req_method\t uri\t version\t Accept-Language\t Accept-Encoding\t Accept-Charset\t Accept\t Content-Type\t Content-Length\t Connection\t User-Agent\t Host\t \
status\t Content-Type\t Content-Length\t Date\n");
			// close file
			if (fp != NULL) {
				fclose(fp);
				fp = NULL;
			}
		}
		// open the file
		fp = fopen(file_name, "a"); 
		if (fp == NULL) {  
			printf("can not open the file:%s\n", file_name);  
			return -1;  
		}
		// write string to file
		// five tuple
		fprintf(fp, "%s\t %s\t %s\t %d\t %d\t ", \
				src_ip, dst_ip, proto->p_name, cdr_info->tuple.src_port, cdr_info->tuple.dst_port);
		// application layer proto
		fprintf(fp, "HTTP\t ");
		// request line 
		fprintf(fp, "%s\t %s\t %s\t ", \
				cdr_info->http_info.request_line.method, cdr_info->http_info.request_line.url, cdr_info->http_info.request_line.version);
		// request field
		for(i = 0; NULL != cdr_http_req_fields[i]; i++) {
			exist = 0;
			for (j = 0; j < cdr_info->http_info.req_hdr.field_num; j++) {
				if (0 == strcmp(cdr_http_req_fields[i], cdr_info->http_info.req_hdr.fields[j].field_name)) {
					fprintf(fp, "%s\t ", cdr_info->http_info.req_hdr.fields[j].field_value);
					exist = 1;
					break;
				}
			}
			if (!exist) {
				fprintf(fp, "\t ");
			}
		}
		// status line
		fprintf(fp, " %s\t ", cdr_info->http_info.status_line.status);
		// response field
		for (i = 0; NULL != cdr_http_resp_fields[i]; i++) {
			exist = 0;
			for (j = 0; j < cdr_info->http_info.resp_hdr.field_num; j++) {
				if (0 == strcmp(cdr_http_resp_fields[i], cdr_info->http_info.resp_hdr.fields[j].field_name)) {
					fprintf(fp, "%s\t ", cdr_info->http_info.resp_hdr.fields[j].field_value);
					exist = 1;
					break;
				}
			}
			if (!exist) {
				fprintf(fp, "\t ");
			}
		}
		fprintf(fp, "\n");
	} else if (cdr_info->app_proto_type == PROTO_FTP_CTR || cdr_info->app_proto_type == PROTO_FTP_DATA) {
		char *file_name = "ftp_cdr.csv";
		// file doesn’t exist
		if (-1 == access(file_name, F_OK)) {
			printf("ftp_cdr.csv file doesn't exist\n");
			fp = fopen(file_name, "a"); 
			if (fp == NULL) {  
				printf("can not open the file:%s\n", file_name);  
				return -1;  
			}
			// write table header to file
			fprintf(fp, "src_add\t dst_add\t transport_layer_proto\t  src_port\t dst_port\t app_proto_type\t \
user\t password\t operation\t file_name\t file_size\n");
			// close file
			if (fp != NULL) {
				fclose(fp);
				fp = NULL;
			}
		}
		// open the file
		fp = fopen(file_name, "a"); 
		if (fp == NULL) {  
			printf("can not open the file:%s\n", file_name);  
			return -1;  
		}
		// write string to file
		// five tuple
		fprintf(fp, "%s\t %s\t %s\t %d\t %d\t ", \
				src_ip, dst_ip, proto->p_name, cdr_info->tuple.src_port, cdr_info->tuple.dst_port);
		// application layer proto
		if (cdr_info->app_proto_type == PROTO_FTP_CTR) { 
			fprintf(fp, "FTP\t ");
			fprintf(fp, "%s\t %s\n", \
					cdr_info->ftp_info.user, cdr_info->ftp_info.password);
		} else {
			fprintf(fp, "FTP-DATA\t ");
			fprintf(fp, "%s\t %s\t %s\t %s\t %s\n", \
					cdr_info->ftp_info.user, cdr_info->ftp_info.password, cdr_info->ftp_info.operation, \
					cdr_info->ftp_info.path, cdr_info->ftp_info.file_size);
		}
	}
    // close file
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
	return 0;  
}