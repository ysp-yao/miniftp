#include "session.h"

#include "tlpi_hdr.h"





void begin_session(session_t *sess) {
  /*int sockfds[2];
  if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds)) {
    errExit("socketpair");
  }*/
  priv_sock_init(sess);

  switch(fork()) {
  case -1:
    errExit("fork");
    break;
  case 0: // child, ftp server process
    //close(sockfds[0]);
    //sess->child_fd = sockfds[1];
    priv_sock_set_child_context(sess);
    handle_child(sess);
    break;

  default: { // parent, nobody process

    priv_sock_set_parent_context(sess);
    //close(sockfds[1]);
    //sess->parent_fd = sockfds[0];
    handle_parent(sess);
    break;
  }
  }

}
