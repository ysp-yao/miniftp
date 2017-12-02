#include "session.h"

#include "str.h"

#include <muduo/base/Logging.h>

#include <string>

#include <unistd.h>


bool Session::init(int cfd) {
  unix_socket_.init();
  ftp_service_.init(cfd);
  
  
}

void Session::start() {

  switch(fork()) {
  case -1:
    //errExit("fork");
    break;
    
  case 0: // child, ftp server process
    ftp_service_process();
    break;

  default: // parent, nobody process
    nobody_process();
    break;
  }
}


void Session::ftp_service_process() {
  LOG_INFO << "child, ftp server process";
  ftp_service_.SendToClient(FTP_GREET, "(miniftpd 0.1)");

  std::string msg, cmd, args;
  while (1) {
    ftp_service_.ReadFromClient(msg);
    str_split(msg, cmd, args, ' ');
    LOG_INFO << "[cmd]=" << cmd << " [args]=" << args;

  }
}

void Session::nobody_process() {
  LOG_INFO << "parent, nobody process";
  while(1);
}