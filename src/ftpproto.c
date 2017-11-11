#include "ftpproto.h"

#include "rdwrn.h"
#include "read_line.h"
#include "str.h"


#include <string.h>
#include <stdio.h>
#include <stdlib.h>


void handle_child(session_t *sess) {
  writen(sess->ctrl_fd, "220 (miniftpd 0.1)\r\n", strlen("220 (miniftpd 0.1)\r\n"));
  int ret;
  while (1) {
    memset(sess->cmdline, 0, sizeof(sess->cmdline));
    memset(sess->cmd, 0, sizeof(sess->cmd));
    memset(sess->arg, 0, sizeof(sess->arg));
    ret = readLine(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
    if (ret == -1) {
      errExit("readLine");
    }
    else if (ret == 0) {
      exit(EXIT_SUCCESS);
    }
    str_trim_crlf(sess->cmdline);
    printf("cmdline=[%s]\n", sess->cmdline);
    
    str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
    printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
    
    str_upper(sess->cmd);
  }
}