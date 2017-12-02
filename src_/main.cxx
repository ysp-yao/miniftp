
//#include "ftp_service.h"


#include "session.h"
#include <muduo/base/Logging.h>
#include "inet_sockets.h"

#include <memory>



int main() {



  int lfd, cfd;
  char port[] = "5188";
  lfd = inetListen(port, SOMAXCONN, NULL);
  LOG_INFO << "miniftp listen on port " << port;

  for(;;) {
    cfd = accept(lfd, NULL, NULL);
    if (cfd == -1) {
      LOG_ERROR << "accept";
    }
    LOG_INFO << "new client, cfd is " << cfd;

    switch (fork()) {
      case -1: {
        LOG_ERROR << "fork";
        break;
      }
      case 0: {// child
        close(lfd);
        std::shared_ptr<Session> p_session = std::make_shared<Session>();
        p_session->init(cfd);
        p_session->start();
        //begin_session(cfd);
        break;
      }
      default: {// parent
        close(cfd);
        break;
      }
    }
  }

  return 0;
}
