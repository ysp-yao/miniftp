#include "ftp_service.h"


#include <muduo/base/Logging.h>

#include "rdwrn.h"
#include "read_line.h"

#include <stdio.h>
#include <string.h>

FtpService::FtpService() {
  
}

void FtpService::init(int tcp_sock_fd) {
  tcp_sock_fd_ = tcp_sock_fd;
}

void FtpService::SendToClient(int status, const char *text) {
  char buf[1024] = {0};
  LOG_INFO << "[SEND]" << status << " " << text;
  sprintf(buf, "%d %s\r\n", status, text);
  writen(tcp_sock_fd_, buf, strlen(buf));

}

int FtpService::ReadFromClient(std::string &msg) {
  char c_msg[1024];
  readLine(tcp_sock_fd_, c_msg, 1024);
  char *p = &c_msg[strlen(c_msg)-1];
  while (*p == '\r' || *p == '\n') {
    *p-- = '\0';
  }
  msg = c_msg;
  LOG_INFO << "[RECV]" << msg;
}