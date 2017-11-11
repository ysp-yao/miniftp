#include "session.h"


#include "tlpi_hdr.h"
#include "inet_sockets.h"

int main(int argc, char *argv[]) {

  if (getuid() != 0) {
    errExit("miniftpd must be started as root");  
  }

  session_t sess = {
    -1, "", "", "",
    -1,-1
  };


  int lfd, cfd;

  char port[10] = "5188";
  lfd = inetListen(port, SOMAXCONN, NULL);

  for(;;) {
    cfd = accept(lfd, NULL, NULL);
    if (cfd == -1) {  
      errExit("accept");  
    }

  switch (fork()) {
  case -1: 
    errExit("fork");  
    break;

  case 0:// child
    close(lfd);
    sess.ctrl_fd = cfd;
    begin_session(&sess);
    break;

  default:// parent
    close(cfd);
    break;
  }
  }

  return 0;
}
