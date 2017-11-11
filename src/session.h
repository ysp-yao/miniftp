#ifndef SESSION_H_
#define SESSION_H_

#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024

typedef struct session {
  int ctrl_fd;
  char cmdline[MAX_COMMAND_LINE];
  char cmd[MAX_COMMAND];
  char arg[MAX_ARG];
  

  int parent_fd;
  int child_fd;

} session_t;



void begin_session(session_t *sess);



#endif // SESSION_H_
