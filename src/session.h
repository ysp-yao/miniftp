#ifndef SESSION_H_
#define SESSION_H_

#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024

#include <sys/types.h>

typedef struct session {
  
  uid_t uid;
  int ctrl_fd;
  char cmdline[MAX_COMMAND_LINE];
  char cmd[MAX_COMMAND];
  char arg[MAX_ARG];
  
  char ip[100];
  int port;
  //struct sockaddr_in *port_addr;
  int data_fd;
  int pasv_listen_d;
  
  unsigned int bw_upload_rate_max;
  unsigned int bw_download_rate_max;
  long bw_transfer_start_sec;
  long bw_transfer_start_usec;
  
  int parent_fd;
  int child_fd;
  
  int is_ascii;
  long long restart_pos;
  char *rnfr_name;

} session_t;



void begin_session(session_t *sess);



#endif // SESSION_H_
