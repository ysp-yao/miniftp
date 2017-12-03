#include "nobody.h"
#include "unix_socket.h"

#include <muduo/base/Logging.h>

void Nobody::init(UnixSocket *p_unix_socket) {
  p_unix_socket_ = p_unix_socket;
  unix_sock_fd_ = p_unix_socket_->parent_fd();
}

void Nobody::run() {
  LOG_INFO << "parent, nobody process";
  while(1);
}
