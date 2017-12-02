#ifndef SESSION_H_
#define SESSION_H_

#include "unix_socket.h"
#include "ftp_service.h"

class Session {
  
public:
  bool init(int cfd);
  void start();
  
private:
  void ftp_service_process();
  void nobody_process();

private:
  UnixSocket unix_socket_;
  FtpService ftp_service_;
};




#endif // SESSION_H_