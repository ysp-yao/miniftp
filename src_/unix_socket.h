#ifndef UNIX_SOCKET_H_
#define UNIX_SOCKET_H_

class UnixSocket {
public:
  UnixSocket();

  bool init();
  int parent_fd();
  int child_fd();
private:
  int sockfd_[2];
  
};




#endif // UNIX_SOCKET_H_