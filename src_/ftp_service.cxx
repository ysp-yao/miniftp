#include "ftp_service.h"
#include "unix_socket.h"

#include "str.h"
#include <muduo/base/Logging.h>

#include "rdwrn.h"
#include "read_line.h"

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/stat.h>


static int tunable_pasv_enable = 1;
static int tunable_port_enable = 1;
static unsigned int tunable_listen_port = 21;
static unsigned int tunable_max_clients = 2000;
static unsigned int tunable_max_peer_ip = 50;
static unsigned int tunable_accept_time = 60;
static unsigned int tunable_connect_timeout = 300;
static unsigned int tunable_idle_session_timeout = 21;
static unsigned int tunable_data_connection_timeout = 300;
static unsigned int tunable_local_umask = 50;
static unsigned int tunable_upload_max_rate = 50;
static unsigned int tunable_download_max_rate = 50;
static const char *tunable_listen_address;


std::map<std::string, std::function<void(FtpService *, std::string)>> FtpService::ftp_function_map_ = {
  {"USER", FtpService::do_user},
  {"PASS", FtpService::do_pass},
  {"SYST", FtpService::do_syst},
  {"FEAT", FtpService::do_feat},
  {"TYPE", FtpService::do_type},
  {"PASV", FtpService::do_pasv},

};



FtpService::FtpService() {

}

void FtpService::init(UnixSocket *p_unix_socket, int tcp_sock_fd) {
  tcp_sock_fd_ = tcp_sock_fd;
  p_unix_socket_ = p_unix_socket;
  unix_sock_fd_ = p_unix_socket_->child_fd();
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

void FtpService::run() {
  LOG_INFO << "child, ftp server process";
  SendToClient(FTP_GREET, "(miniftpd 0.1)");


  while (1) {
    std::string msg, cmd, args;
    ReadFromClient(msg);
    str_split(msg, cmd, args, ' ');
    LOG_INFO << "[cmd]=" << cmd << " [args]=" << args;
    
    if (ftp_function_map_.find(cmd) != ftp_function_map_.end()) {
      if (ftp_function_map_[cmd]) {
        ftp_function_map_[cmd](this, args);
      }
      else {
        SendToClient(FTP_COMMANDNOTIMPL, "Unimplement command.");
      }
    }
    else {
      SendToClient(FTP_BADCMD, "Unknown command.");
    }
  }
}


void FtpService::do_user(FtpService *p, std::string args) {
  LOG_INFO << "do_user()";
  struct passwd *pw = getpwnam(args.c_str());
  if (pw == NULL) {
    p->SendToClient(FTP_LOGINERR, "Login incorrect.");
    return;
  }
  p->user_id_ = pw->pw_uid;
  p->SendToClient(FTP_GIVEPWORD, "Please specify the password.");
}

void FtpService::do_pass(FtpService *p, std::string args) {
  LOG_INFO << "do_pass()";
  struct passwd *pw = getpwuid(p->user_id_);
  if (pw == NULL) {
    p->SendToClient(FTP_LOGINERR, "Login incorrect.");
    return;
  }
  
  struct spwd *sp = getspnam(pw->pw_name);
  if(sp == NULL) {
    p->SendToClient(FTP_LOGINERR, "Login incorrect.");
    return;
  }
  
  char *encrypted_pass = crypt(args.c_str(), sp->sp_pwdp);
  if (strcmp(encrypted_pass, sp->sp_pwdp) != 0) {
    p->SendToClient(FTP_LOGINERR, "Login incorrect.");
    return;
  }
  
  umask(tunable_local_umask);
  setegid(pw->pw_gid);
  seteuid(pw->pw_uid);
  chdir(pw->pw_dir);
  
  p->SendToClient(FTP_LOGINOK, "Login successful.");
}

void FtpService::do_syst(FtpService *p, std::string args) {
  p->SendToClient(FTP_SYSTOK, "UNIX Type: L8");
}

void FtpService::do_feat(FtpService *p, std::string args) {
  p->SendToClient(FTP_FEAT, "Features:");
  writen(p->tcp_sock_fd_, " EPRT\r\n", strlen(" EPRT\r\n"));
  writen(p->tcp_sock_fd_, " EPSV\r\n", strlen(" EPSV\r\n"));
  writen(p->tcp_sock_fd_, " MDTM\r\n", strlen(" MDTM\r\n"));
  writen(p->tcp_sock_fd_, " PASV\r\n", strlen(" PASV\r\n"));
  writen(p->tcp_sock_fd_, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
  writen(p->tcp_sock_fd_, " SIZE\r\n", strlen(" SIZE\r\n"));
  writen(p->tcp_sock_fd_, " TVFS\r\n", strlen(" TVFS\r\n"));
  writen(p->tcp_sock_fd_, " UTF8\r\n", strlen(" UTF8\r\n"));
  p->SendToClient(FTP_FEAT, "End");
}

void FtpService::do_type(FtpService *p, std::string args) {
  if (args == "A") {
    p->is_ascii_ = 1;
    p->SendToClient(FTP_TYPEOK, "Switch to ASCII mode.");
  }
  else if (args == "I") {
    p->is_ascii_ = 0;
    p->SendToClient(FTP_TYPEOK, "Switch to Binary mode.");
  }
  else {
    p->SendToClient(FTP_BADCMD, "Unrecognised TYPE command.");
  }
}

void FtpService::do_pasv(FtpService *p, std::string args) {
/*   priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
  unsigned short port = (int)priv_sock_get_int(sess->child_fd);
  
  printf("do_pasv:sess:%d\n",sess);
  printf("do_pasv:sess->pasv_listen_d:%d\n",sess->pasv_listen_d);

  unsigned int v[4];
  char localip[50] = "192.168.137.248";
  sscanf(localip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
  char text[1024] = {0};
  sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
    v[0], v[1], v[2], v[3], port>>8, port&0xFF);
    
  ftp_reply(sess, FTP_PASVOK, text); */
}








