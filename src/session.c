#include "session.h"

#include "tlpi_hdr.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>


void begin_session(session_t *sess) {
  struct passwd *pw = getpwnam("nobody");
  if (pw == NULL) {
    return;  
  }
  
  if (setgid(pw->pw_gid)<0) {
    errExit("setgid");
  }	  

  if (setuid(pw->pw_uid)<0) {
    errExit("setuid");
  }	  

  
  int sockfds[2];
  if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds)) {
    errExit("socketpair");
  }

  switch(fork()) {
  case -1:
    errExit("fork");
    break;
  case 0: // child, ftp server process
    close(sockfds[0]);
    sess->child_fd = sockfds[1];
    handle_child(sess);
    break;

  default: // parent, nobody process
    close(sockfds[1]);
    sess->parent_fd = sockfds[0];
    handle_parent(sess);
    break;

  }

}
