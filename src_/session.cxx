#include "session.h"

#include "str.h"

#include <muduo/base/Logging.h>

#include <string>

#include <unistd.h>


bool Session::init(int cfd) {
  unix_socket_.init();
  ftp_service_.init(&unix_socket_, cfd);
  nobody_.init(&unix_socket_);
  
}

void Session::start() {
  switch(fork()) {
  case -1:

    break;
    
  case 0: // child, ftp server process
    ftp_service_.run();
    break;

  default: // parent, nobody process
    nobody_.run();
    break;
  }
}


