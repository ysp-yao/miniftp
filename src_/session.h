#ifndef SESSION_H_
#define SESSION_H_

#include "unix_socket.h"
#include "ftp_service.h"
#include "nobody.h"


class Session {
  
public:
  bool init(int cfd);
  void start();

private:
  UnixSocket unix_socket_;
  FtpService ftp_service_;
  Nobody nobody_;
};




#endif // SESSION_H_