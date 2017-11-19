#include "privparent.h"
#include "privsock.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>
#include <netinet/in.h>
#include <linux/capability.h>
#include <sys/syscall.h>

static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

int capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
  return syscall(__NR_capset, hdrp, datap);
}


void minimize_privilege() {
  struct passwd *pw = getpwnam("nobody");
  if (pw == NULL) {
    return;  
  }
  printf("+++++++\n");
  if (setgid(pw->pw_gid)<0) {
    errExit("setgid");
  }  

  if (setuid(pw->pw_uid)<0) {
    errExit("setuid");
  }  
  
  struct __user_cap_header_struct cap_header;
  struct __user_cap_data_struct cap_data;
  
  memset(&cap_header, 0, sizeof(cap_header));
  memset(&cap_data, 0, sizeof(cap_data));
  
  cap_header.version = _LINUX_CAPABILITY_VERSION_1;
  cap_header.pid = 0;
  
  __u32 cap_mask = 0;
  cap_mask |= (1 << CAP_NET_BIND_SERVICE);
  
  cap_data.effective = cap_data.permitted = cap_mask;
  cap_data.inheritable = 0;
  
  capset(&cap_header, &cap_data);
}


void handle_parent(session_t *sess) {

  minimize_privilege();
  
  char cmd;
  while (1) {
    //read(sess->parent_fd, &cmd, 1);
    cmd = priv_sock_get_cmd(sess->parent_fd);
    
    switch (cmd) {
      case PRIV_SOCK_GET_DATA_SOCK:
        privop_pasv_get_data_sock(sess);
        break;
      case PRIV_SOCK_PASV_ACTIVE:
        privop_pasv_active(sess);
        break;
      case PRIV_SOCK_PASV_LISTEN:
        privop_pasv_listen(sess);
        break;
      case PRIV_SOCK_PASV_ACCEPT:
        privop_pasv_accept(sess);
        break;
      
    }
  }
}

static void privop_pasv_get_data_sock(session_t *sess) {
  printf("ssssss\n");
  int port = priv_sock_get_int(sess->parent_fd);
  char ip[16] = {0};
  priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
  
  printf("%d\n", port);
  printf("%s\n", ip);
  

  
  /*
  int clt_sock = socket(AF_INET, SOCK_STREAM, 0);   
  if(clt_sock < 0) {
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
    return;
    //errExit("socket");
  }*/
  

  int sock;
  
  // 1
  //sock = inetBind("20", SOCK_STREAM, NULL);

  // 2
  /*
  sock = socket(AF_INET, SOCK_STREAM, 0);   
  if(sock < 0) {
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
    return;
    //errExit("socket");
  }
  */
  
  // 3
  sock = socket(AF_INET, SOCK_STREAM, 0);   
  if(sock < 0) {
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
    return;
    //errExit("socket");
  }
  
  int on = 1;
  int local_port = 2188;
  if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) < 0) {
    errExit("setsockopt");
  }
 
  struct sockaddr_in local_addr;
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons(local_port);
  local_addr.sin_addr.s_addr = inet_addr("192.168.137.248");
  if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
    errExit("bind");
  }
  
  //////////////////////////////////
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);
  socklen_t addr_len = sizeof(addr);  
  int connect_fd = connect(sock, (struct sockaddr*)&addr, addr_len);  
  if(connect_fd < 0) {
    close(sock);
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
    return;
    //errExit("connect");
  }
  
  priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
  priv_sock_send_fd(sess->parent_fd, sock);
  close(sock);
  
}
static void privop_pasv_active(session_t *sess) {
  int active;
  if (sess->pasv_listen_d != -1) {
    active = 1;
  }
  else {
    active = 0;    
  }
  priv_sock_send_int(sess->parent_fd, active);
}
static void privop_pasv_listen(session_t *sess) {
  char localip[50] = "192.168.137.144";
  char portt[10] = "2188";
  if ((sess->pasv_listen_d = inetListen(portt, SOMAXCONN, NULL)) == -1) {
    errExit("inetBind");
  }
  printf("privop_pasv_active:sess:%d\n",sess);
  printf("privop_pasv_active:sess->pasv_listen_d:%d\n",sess->pasv_listen_d);
  struct sockaddr_in addr;
  socklen_t addlen = sizeof(addr);
  memset(&addr, 0, addlen);
  if(getsockname(sess->pasv_listen_d, (struct sockaddr *)&addr, &addlen)<0) {
    errExit("getsockname");
  }
  if(getsockname(sess->pasv_listen_d, (struct sockaddr *)&addr, &addlen)<0) {
    errExit("getsockname");
  }
  printf("privop_pasv_active:sess->pasv_listen_d:%d\n",sess->pasv_listen_d);
  unsigned short port = ntohs(addr.sin_port);
  
  
  priv_sock_send_int(sess->parent_fd, (int)port);
  printf("privop_pasv_active:sess->pasv_listen_d:%d\n",sess->pasv_listen_d);
}

static void privop_pasv_accept(session_t *sess) {
     
    int cfd = accept(sess->pasv_listen_d, NULL, NULL);
    close(sess->pasv_listen_d);
    sess->pasv_listen_d = -1;
    if (cfd ==-1) {
      priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
      return;
    }
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
    priv_sock_send_fd(sess->parent_fd, cfd);
    close(cfd);
}

