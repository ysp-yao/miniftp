#ifndef NOBODY_H_
#define NOBODY_H_

class UnixSocket;

class Nobody {
  
public:
  void init(UnixSocket *p_unix_socket);
  void run();
  
private:
  UnixSocket *p_unix_socket_;
  int unix_sock_fd_;
  
};

#endif // NOBODY_H_