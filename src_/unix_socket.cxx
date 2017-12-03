#include "unix_socket.h"

#include <muduo/base/Logging.h>

#include <sys/types.h>
#include <sys/socket.h>


UnixSocket::UnixSocket() {
  sockfd_[0] = -1;
  sockfd_[1] = -1;
}

bool UnixSocket::init() {
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd_)) {
    LOG_ERROR << "socketpair";
  }
}

int UnixSocket::parent_fd() {
  close(sockfd_[1]);
  return sockfd_[0];
}

int UnixSocket::child_fd() {
  close(sockfd_[0]);
  return sockfd_[1];
}
