#ifndef PARSE_APP_PROTO_H_
#define PARSE_APP_PROTO_H_

#include <stdint.h>
#include <time.h>

#include "parse_l2_to_l4_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROTO_UNKNOWN		    0x00
#define PROTO_HTTP			    0x01
#define PROTO_FTP_CTR			0x02
#define PROTO_FTP_DATA			0x03

#define FTP_USER_SIZE    256
#define FTP_PWD_SIZE     16
#define FTP_PATH_SIZE    128
#define FTP_CMD_SIZE     16
#define FTP_FILE_SIZE    32

#define HTTP_METHOD_SIZE         8
#define HTTP_VER_SIZE            16
#define HTTP_URL_SIZE            2048
#define HTTP_STATUS_SIZE         64
#define HTTP_FIELD_NAME_SIZE     16
#define HTTP_FIELD_VALUE_SIZE    256
#define HTTP_FIELD_MAX           16



typedef struct {
	five_tuple tuple;                           // five tuple of the ftp control connection
	uint16_t srv_port;                          // ftp data connection port of the server
} ctr_to_data_conn;

// call detail record struct
typedef struct {
	char user[FTP_USER_SIZE]; 					// user
	char password[FTP_PWD_SIZE];                // password
	char operation[FTP_CMD_SIZE];               // Operation
	char path[FTP_PATH_SIZE];                   // path name
	char file_size[FTP_FILE_SIZE];              // file size
	uint16_t cli_port;                          // data connection port of the client
	uint16_t srv_port;                          // data connection port of the server
	uint8_t flag;                               // copy the control connection information to the data connection flag
}ftp_cdr;

struct fields {
	uint8_t field_num;                              // field number
	struct {
		char field_name[HTTP_FIELD_NAME_SIZE];      // field name
		char field_value[HTTP_FIELD_VALUE_SIZE];    // field value
		uint16_t field_name_len;                    // field name length
		uint16_t field_value_len;                   // field value length
	} fields[HTTP_FIELD_MAX];
};
typedef struct {
	struct {
		char method[HTTP_METHOD_SIZE];          // method
		char url[HTTP_URL_SIZE];                // url
		char version[HTTP_VER_SIZE];            // http version
	} request_line;
	struct fields req_hdr;                      // request fields
	struct {
		char version[HTTP_VER_SIZE];            // http version
		char status[HTTP_STATUS_SIZE];          // status
	} status_line;
	struct fields resp_hdr;                     // response fields
} http_cdr;

// flow table item
typedef struct {
	five_tuple tuple;                           // five tuple
	uint8_t app_proto_type;                     // application layer protocol
	struct timespec timestamp;                  // for flow table aging
	union {
		ftp_cdr ftp_info;
		http_cdr http_info;
	};
} cdr;

// mapping of control connections and data connections
extern ctr_to_data_conn g_http_ctr_to_data_conn;

int parse_app_proto_info(uint8_t *payload, cdr *cdr_info);

#ifdef __cplusplus
}
#endif

#endif /* PARSE_APP_PROTO_H_ */