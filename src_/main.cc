
#include "ftp_service.h"

#include <muduo/base/Logging.h>

#include "error_functions.h"
#include "inet_sockets.h"

void begin_session(int cfd) {
  switch(fork()) {
  case -1:
    errExit("fork");
    break;
    
  case 0: // child, ftp server process
    LOG_INFO << "child, ftp server process";
    while (1);
    break;

  default: // parent, nobody process
    LOG_INFO << "parent, nobody process";
    while (1);
    break;
  }
}


int main() {

  int lfd, cfd;
  char port[] = "5188";
  lfd = inetListen(port, SOMAXCONN, NULL);
  LOG_INFO << "miniftp listen on port " << port;

  for(;;) {
    cfd = accept(lfd, NULL, NULL);
    if (cfd == -1) {
      LOG_ERROR << "accept";
      errExit("accept");
    }
    LOG_INFO << "new client, cfd is " << cfd;

    switch (fork()) {
    case -1: 
      errExit("fork");  
      break;

    case 0:// child
      close(lfd);
      begin_session(cfd);
      break;

    default:// parent
      close(cfd);
      break;
    }
  }



  return 0;
}