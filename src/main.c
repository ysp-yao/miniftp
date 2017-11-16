#include "session.h"


#include "tlpi_hdr.h"
#include "inet_sockets.h"

#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"


int main(int argc, char *argv[]) {

  //list_common();

  parseconf_load_file("../src/miniftpd.conf");

  printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
  printf("tunable_port_enable=%d\n", tunable_port_enable);

  printf("tunable_listen_port=%u\n", tunable_listen_port);
  printf("tunable_max_clients=%u\n", tunable_max_clients);
  printf("tunable_max_peer_ip=%u\n", tunable_max_peer_ip);
  printf("tunable_accept_time=%u\n", tunable_accept_time);
  printf("tunable_connect_timeout=%u\n", tunable_connect_timeout);
  printf("tunable_idle_session_timeout=%u\n", tunable_idle_session_timeout);
  printf("tunable_data_connection_timeout=%u\n", tunable_data_connection_timeout);
  printf("tunable_local_umask=%u\n", tunable_local_umask);
  printf("tunable_upload_max_rate=%u\n", tunable_upload_max_rate);
  printf("tunable_download_max_rate=%u\n", tunable_download_max_rate);
  
  if (tunable_listen_address) {
    printf("tunable_listen_address=%s\n", tunable_listen_address);
  }
  else {
    printf("tunable_listen_address=NULL\n");
  }
  
  
  if (getuid() != 0) {
    errExit("miniftpd must be started as root");  
  }

  session_t sess = {
    0, -1, "", "", "",
    "",-1,-1,-1,
//NULL,-1,
    -1,-1,
    0
  };


  int lfd, cfd;

  char port[10] = "5188";
  //char sss[10] = "2188";
  //lfd = inetListen(sss, SOMAXCONN, NULL);
  lfd = inetListen(port, SOMAXCONN, NULL);

  //while(1);
  for(;;) {
    cfd = accept(lfd, NULL, NULL);
    if (cfd == -1) {  
      errExit("accept");  
    }

  switch (fork()) {
  case -1: 
    errExit("fork");  
    break;

  case 0:// child
    close(lfd);
    sess.ctrl_fd = cfd;
    begin_session(&sess);
    break;

  default:// parent
    close(cfd);
    break;
  }
  }

  return 0;
}
