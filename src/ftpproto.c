#include "ftpproto.h"
#include "rdwrn.h"
#include "read_line.h"
#include "str.h"
#include "ftpcodes.h"
#include "privsock.h"
#include "tunable.h"

#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


#include <string.h>
#include <stdio.h>
#include <stdlib.h>



void ftp_reply(session_t *sess, int status, const char *text);
void ftp_lreply(session_t *sess, int status, const char *text);

int get_transfer_fd(session_t *sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);



int lock_internal(int fd, int lock_type) {
  int ret;
  
  struct flock the_lock;
  memset(&the_lock, 0, sizeof(the_lock));
  the_lock.l_type = lock_type;
  the_lock.l_whence = SEEK_SET;
  the_lock.l_start = 0;
  the_lock.l_len = 0;
  
  do {
    ret = fcntl(fd, F_SETLKW, &the_lock);
  }
  while (ret<0 && errno == EINTR);
  return ret;
}


int unlock_file(int fd) {
  int ret;
  
  struct flock the_lock;
  memset(&the_lock, 0, sizeof(the_lock));
  the_lock.l_type = F_UNLCK;
  the_lock.l_whence = SEEK_SET;
  the_lock.l_start = 0;
  the_lock.l_len = 0;
  

  ret = fcntl(fd, F_SETLK, &the_lock);

  return ret;
}



int lock_file_write(int fd) {
  return lock_internal(fd, F_WRLCK);
}

int lock_file_read(int fd) {
  return lock_internal(fd, F_RDLCK);
}

static struct timeval s_curr_time;

long get_time_sec() {
  if (gettimeofday(&s_curr_time, NULL)) {
    errExit("gettimeofday");
  }
  return s_curr_time.tv_sec;
}

long get_time_usec() {
  return s_curr_time.tv_usec;
}

void nano_sleep(double seconds) {
  time_t secs = (time_t)seconds;
  double fractional = seconds - (double)secs;
  
  struct timespec ts;
  ts.tv_sec = secs;
  ts.tv_nsec = (long)(fractional * (double)1000000000);
  
  int ret;
  do {
    ret = nanosleep(&ts, &ts);
  }
  while (ret == -1 && errno == EINTR);
}

void limit_rate(session_t *sess, int bytes_transfered, int is_upload) {
  long curr_sec = get_time_sec();
  long curr_usec = get_time_usec();
  
  double elapsed;
  elapsed = curr_sec - sess->bw_transfer_start_sec;
  elapsed += (double)(curr_sec - sess->bw_transfer_start_sec) / (double)1000000;
  if (elapsed <= 0) {
    elapsed = 0.01;
  }
  
  
  unsigned int bw_rate = (unsigned int)((double)bytes_transfered/elapsed);
  
  double rate_ratio;
  if (is_upload) {
    if (bw_rate <= sess->bw_upload_rate_max) {
      return;
    }
    rate_ratio = bw_rate / sess->bw_upload_rate_max;
  }
  else {
    if (bw_rate <= sess->bw_download_rate_max) {
      return;
    }
    rate_ratio = bw_rate / sess->bw_download_rate_max;
  }
  
  double pause_time;
  pause_time = (rate_ratio - (double)1) * elapsed;
  
  nano_sleep(pause_time);
  
  sess->bw_transfer_start_sec = get_time_sec();
  sess->bw_transfer_start_usec = get_time_usec();
}


void upload_common(session_t *sess, int is_append) {
  if (get_transfer_fd(sess) == 0) {
    return;
  }
  
  long long offset = sess->restart_pos;
  sess->restart_pos = 0;
  
  int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
  if (fd == -1) {
    ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
    return;    
  }
  
  int ret;
  ret = lock_file_write(fd);
  if (ret == -1) {
    ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
    return;
  }
  
  if (!is_append && offset == 0) { // STOR
    ftruncate(fd, 0);
    if (lseek(fd, 0, SEEK_SET) < 0) {
      ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
      return;
    }
  }
  else if (!is_append && offset != 0) { // REST && STOR
    if (lseek(fd, offset, SEEK_SET) < 0) {
      ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
      return;
    }    
  }
  else if (is_append) { // APPE
     if (lseek(fd, 0, SEEK_SET) < 0) {
      ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
      return;
    }
  }
  
  struct stat sbuf;
  ret = fstat(fd, &sbuf);
  if (!S_ISREG(sbuf.st_mode)) {
    ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
    return;
  }
  
  if (offset != 0) {
    ret = lseek(fd, offset, SEEK_SET);
    if (ret == -1) {
      ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
      return;
    }
  }
  
  
  char text[1024] = {0};
  if (sess->is_ascii) {
    sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes)",
    sess->arg, (long long)sbuf.st_size);
  }
  else {
    sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes)",
    sess->arg, (long long)sbuf.st_size);
  }
  
  ftp_reply(sess, FTP_DATACONN, text);
  
  int flag;
  char buf[1024];
  sess->bw_transfer_start_sec = get_time_sec();
  sess->bw_transfer_start_usec = get_time_usec();
  while (1) {
    ret = read(sess->data_fd, buf, sizeof(buf));
    if (ret == -1) {
      if (errno == EINTR) {
        continue;
      }
      else {
        flag = 2;
        break;
      }
    }
    else if (ret == 0) {
      flag = 0;
      break;
    }
    
    limit_rate(sess, ret, 1);
    
    
    
    if (writen(fd, buf, ret) != ret) {
      flag = 1;
      break;
    }
  }
  /*
  long long bytes_to_send = sbuf.st_size;
  if (offset > bytes_to_send) {
    bytes_to_send = 0;
  }
  else {
    bytes_to_send -= offset;
  }
  
  while (bytes_to_send) {
    int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
    ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
    if (ret == -1) {
      flag = 2;
      break;
    }
    
    bytes_to_send -= ret;
  }
  
  if (bytes_to_send == 0) {
    flag =0;
  }*/
  
  
  close(sess->data_fd);
  sess->data_fd = -1;
  close(fd);
  
  if (flag == 0) {
    ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
  }
  else if (flag == 1) {
    ftp_reply(sess, FTP_BADSENDFILE, "Failure writing to local file.");
  }
  else if (flag== 2) {
    ftp_reply(sess, FTP_BADSENDNET, "Failure reading from network stream.");
  }  
  
}

typedef struct ftpcmd {
  const char *cmd;
  void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

static ftpcmd_t ctrl_cmds[] = {

  { "USER", do_user },
  { "PASS", do_pass },
  { "CWD", do_cwd },
  { "XCWD", do_cdup },
  { "XCUP", do_cdup },
  { "QUIT", do_quit },
  { "ACCT", NULL },
  { "SWNT", NULL },
  { "REIN", NULL },

  
  
  { "PORT", do_port },
  { "PASV", do_pasv },
  { "TYPE", do_type },
  { "STRU", do_stru },
  { "MODE", do_mode },
  
  { "RETR", do_retr },
  { "STOR", do_stor },
  { "APPE", do_appe },
  { "LIST", do_list },
  { "NLST", do_nlst },
  { "REST", do_rest },
  { "ABOR", do_abor },
  { "\377\364\377\362ABOR", do_abor },
  { "PWD", do_pwd },
  { "XPWD", do_pwd },
  { "MKD", do_mkd },
  { "XMKD", do_mkd },
  { "RMD", do_rmd },
  { "XRMD", do_rmd },
  { "DELE", do_dele },
  { "RNFR", do_rnfr },
  { "RNTO", do_rnto },
  { "SITE", do_site },
  { "SYST", do_syst },
  { "FEAT", do_feat },
  { "SIZE", do_size },
  { "STAT", do_stat },
  { "NOOP", do_noop },
  { "HELP", do_help },
  { "STOU", NULL },
  { "ALLO", NULL }
};










void handle_child(session_t *sess) {
  //writen(sess->ctrl_fd, "220 (miniftpd 0.1)\r\n", strlen("220 (miniftpd 0.1)\r\n"));
  ftp_reply(sess, FTP_GREET, "(miniftpd 0.1)");
  int ret;
  while (1) {
    memset(sess->cmdline, 0, sizeof(sess->cmdline));
    memset(sess->cmd, 0, sizeof(sess->cmd));
    memset(sess->arg, 0, sizeof(sess->arg));
    ret = readLine(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
    if (ret == -1) {
      errExit("readLine");
    }
    else if (ret == 0) {
      exit(EXIT_SUCCESS);
    }
    str_trim_crlf(sess->cmdline);
    printf("cmdline=[%s]\n", sess->cmdline);
    
    str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
    printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
    
    str_upper(sess->cmd);
    /*
    if (strcmp("USER", sess->cmd) == 0) {
      do_user(sess);
    }
    else if (strcmp("PASS", sess->cmd) == 0) {
      do_pass(sess);
    }
    */
    int i;
    int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
    for (i=0; i<size; i++) {
      if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0) {
        if (ctrl_cmds[i].cmd_handler != NULL) {
          ctrl_cmds[i].cmd_handler(sess);
        }
        else {
          ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
        }
        break;
      }
    }
    if (i == size) {
      ftp_reply(sess, FTP_BADCMD, "Unknown command.");
    }
  }
}

static void do_user(session_t *sess) {
  struct passwd *pw = getpwnam(sess->arg);
  if (pw == NULL) {
    ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
    return;
  }
  sess->uid = pw->pw_uid;
  ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
}

static void do_pass(session_t *sess) {
  struct passwd *pw = getpwuid(sess->uid);
  if (pw == NULL) {
    ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
    return;
  }
  
  struct spwd *sp = getspnam(pw->pw_name);
  if(sp == NULL) {
    ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
    return;
  }
  
  char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
  if (strcmp(encrypted_pass, sp->sp_pwdp) != 0) {
    ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
    return;
  }
  
  umask(tunable_local_umask);
  setegid(pw->pw_gid);
  seteuid(pw->pw_uid);
  chdir(pw->pw_dir);
  
  ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

void ftp_reply(session_t *sess, int status, const char *text) {
  char buf[1024] = {0};
  sprintf(buf, "%d %s\r\n", status, text);
  writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lreply(session_t *sess, int status, const char *text) {
  char buf[1024] = {0};
  sprintf(buf, "%d-%s\r\n", status, text);
  writen(sess->ctrl_fd, buf, strlen(buf));
}

static void do_cwd(session_t *sess) {
  if (chdir(sess->arg) < 0) {
    ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");  
    return;
  }
  ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_cdup(session_t *sess) {
  if (chdir("..") < 0) {
    ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");  
    return;
  }
  ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}
static void do_quit(session_t *sess) {
}
static void do_port(session_t *sess) {


  char *p = sess->arg;
  int i=0;
  for (;*p!='\0';++p) {
    if (*p == ',') {

      if (i == 3) {
        *p = '\0';
        ++p;
        break;
      }
      else {
        *p = '.';
        ++i;
      }
    }
  }
  
  strcpy(sess->ip, sess->arg);

  char *p2 = p;
  for (;*p!=',';++p);
  *p = '\0';
  int aaa = atoi(p2);
  int bbb = atoi(++p);
  sess->port = aaa*256+bbb;
  
  

  printf("ip=%s,port=%d\n", sess->ip, sess->port);  

  
  /*
  unsigned int v[6];
  sscanf(sess->arg, "%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
  sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
  memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
  sess->port_addr->sin_family = AF_INET;
  unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
  p[0] = v[0];
  p[1] = v[1];
  
  p = (unsigned char *)&sess->port_addr->sin_addr;
  p[0] = v[2];
  p[1] = v[3];
  p[2] = v[4];
  p[3] = v[5];  
*/
  ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV");

}
static void do_pasv(session_t *sess) {
  /*
//  if ((sess->pasv_listen_d=inetBind("66666666", SOCK_STREAM, NULL)) == -1) {
  char portt[10] = "2188";
  if ((sess->pasv_listen_d = inetListen(portt, SOMAXCONN, NULL)) == -1) {
    errExit("inetBind");
  }

  struct sockaddr_in addr;
  socklen_t addlen = sizeof(addr);
  memset(&addr, 0, addlen);
  if(getsockname(sess->pasv_listen_d, (struct sockaddr *)&addr, &addlen)<0) {
    errExit("getsockname");
  }
    if(getsockname(sess->pasv_listen_d, (struct sockaddr *)&addr, &addlen)<0) {
    errExit("getsockname");
  }
  
  unsigned short port = ntohs(addr.sin_port);
  */
  priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
  unsigned short port = (int)priv_sock_get_int(sess->child_fd);
  
  printf("do_pasv:sess:%d\n",sess);
  printf("do_pasv:sess->pasv_listen_d:%d\n",sess->pasv_listen_d);

  unsigned int v[4];
  char localip[50] = "192.168.137.248";
  sscanf(localip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
  char text[1024] = {0};
  sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
    v[0], v[1], v[2], v[3], port>>8, port&0xFF);
    
  ftp_reply(sess, FTP_PASVOK, text);
}
static void do_type(session_t *sess) {
  if (strcmp(sess->arg, "A") == 0) {
    sess->is_ascii = 1;
    ftp_reply(sess, FTP_TYPEOK, "Switch to ASCII mode.");
  }
  else if (strcmp(sess->arg, "I") == 0) {
    sess->is_ascii = 0;
    ftp_reply(sess, FTP_TYPEOK, "Switch to Binary mode.");
  }
  else {
    ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
  }
}
static void do_stru(session_t *sess) {
}
static void do_mode(session_t *sess) {
}




static void do_retr(session_t *sess) {
  if (get_transfer_fd(sess) == 0) {
    return;
  }
  
  long long offset = sess->restart_pos;
  sess->restart_pos = 0;
  
  int fd = open(sess->arg, O_RDONLY);
  if (fd == -1) {
    ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
    return;    
  }
  
  int ret;
  ret = lock_file_read(fd);
  if (ret == -1) {
    ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
    return;
  }
  
  struct stat sbuf;
  ret = fstat(fd, &sbuf);
  if (!S_ISREG(sbuf.st_mode)) {
    ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
    return;
  }
  
  if (offset != 0) {
    ret = lseek(fd, offset, SEEK_SET);
    if (ret == -1) {
      ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
      return;
    }
  }
  
  
  char text[1024] = {0};
  if (sess->is_ascii) {
    sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes)",
    sess->arg, (long long)sbuf.st_size);
  }
  else {
    sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes)",
    sess->arg, (long long)sbuf.st_size);
  }
  
  ftp_reply(sess, FTP_DATACONN, text);
  
  int flag;
  /*char buf[4096];
  while (1) {
    ret = read(fd, buf, sizeof(buf));
    if (ret == -1) {
      if (errno == EINTR) {
        continue;
      }
      else {
        flag = 1;
        break;
      }
    }
    else if (ret == 0) {
      flag = 0;
      break;
    }
    
    if (writen(sess->data_fd, buf, ret) != ret) {
      flag = 2;
      break;
    }
  }*/
  
  long long bytes_to_send = sbuf.st_size;
  if (offset > bytes_to_send) {
    bytes_to_send = 0;
  }
  else {
    bytes_to_send -= offset;
  }
  
  sess->bw_transfer_start_sec = get_time_sec();
  sess->bw_transfer_start_usec = get_time_usec();
  while (bytes_to_send) {
    int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
    ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
    if (ret == -1) {
      flag = 2;
      break;
    }
    
    limit_rate(sess, ret, 0);
    bytes_to_send -= ret;
  }
  
  if (bytes_to_send == 0) {
    flag =0;
  }
  
  
  close(sess->data_fd);
  sess->data_fd = -1;
  close(fd);
  if (flag == 0) {
    ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
  }
  else if (flag == 1) {
    ftp_reply(sess, FTP_BADSENDFILE, "Failure reading ftom local file.");
  }
  else if (flag== 2) {
    ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
  }
}

static void do_stor(session_t *sess) {
  upload_common(sess, 0);
}
static void do_appe(session_t *sess) {
}
static void do_list(session_t *sess) {

  printf("do_list:sess->pasv_listen_d:%d\n",sess->pasv_listen_d);
  if (get_transfer_fd(sess) == 0) {
    return;
  }
  
  
  
  // 150
  ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
  
  list_common(sess);
  
  close(sess->data_fd);
  sess->data_fd = -1;
  
  ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}
static void do_nlst(session_t *sess) {
}
static void do_rest(session_t *sess) {
  sess->restart_pos = str_to_longlong(sess->arg);
  char text[1024] = {0};
  sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
  ftp_reply(sess, FTP_RESTOK, text);
}
static void do_abor(session_t *sess) {
}
static void do_pwd(session_t *sess) {
  char text[1024] = {0};
  char dir[1024+1] = {0};
  getcwd(dir, 1024);
  sprintf(text, "\"%s\"", dir);
  ftp_reply(sess, FTP_PWDOK, text);
}
static void do_mkd(session_t *sess) {
  
  // 0777 & 0777
  if (mkdir(sess->arg, 0777) < 0) {
    ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
    return;
  }
  
  char text[4096] = {0};
  if (sess->arg[0] == '/') {
    sprintf(text, "%s created", sess->arg);
  }
  else {
    char dir[4096] = {0};
    getcwd(dir, 4096);
    if (dir[strlen(dir)-1] == '/') {
      sprintf(text, "%s%s created", dir, sess->arg);
    }
    else {
      sprintf(text, "%s/%s created", dir, sess->arg);
    }
  }
  
  ftp_reply(sess, FTP_MKDIROK, text);
}
static void do_rmd(session_t *sess) {
  if (rmdir(sess->arg) < 0) {
    ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
  }
    ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}
static void do_dele(session_t *sess) {
  if (unlink(sess->arg) < 0) {
    ftp_reply(sess, FTP_FILEFAIL, "Delete operation fialed.");
    return;
  }
  
  ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}
static void do_rnfr(session_t *sess) {
  sess->rnfr_name = (char *)malloc(strlen(sess->arg)+1);
  memset(sess->rnfr_name, 0, strlen(sess->arg)+1);
  strcpy(sess->rnfr_name, sess->arg);
  ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
static void do_rnto(session_t *sess) {
  if (sess->rnfr_name == NULL) {
    ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
    return;
  }
  rename(sess->rnfr_name, sess->arg);
  ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
  
  free(sess->rnfr_name);
  sess->rnfr_name = NULL;
}
static void do_site(session_t *sess) {
}
static void do_syst(session_t *sess) {
  ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}
static void do_feat(session_t *sess) {
  ftp_lreply(sess, FTP_FEAT, "Features:");
  writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
  writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
  writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
  writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
  writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
  writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
  writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
  writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
  ftp_reply(sess, FTP_FEAT, "End");
}
static void do_size(session_t *sess) {
  struct stat buf;
  if (stat(sess->arg, &buf) < 0) {
    ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed");
    return;
  }
  
  if (!S_ISREG(buf.st_mode)) {
    ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
    return;
  }
  
  char text[1024] = {0};
  sprintf(text, "%lld", buf.st_size);
  ftp_reply(sess, FTP_SIZEOK, text);
}
static void do_stat(session_t *sess) {
}
static void do_noop(session_t *sess) {
}
static void do_help(session_t *sess) {
}

int list_common(session_t *sess, int detail) {
  DIR *dir = opendir(".");
  if (dir == NULL) {
    return 0;
  }
  
  struct dirent *dt;
  struct stat sbuf;
  while ((dt = readdir(dir)) != NULL) {
    if (lstat(dt->d_name, &sbuf) < 0) {
      continue;
    }
    
    if (dt->d_name[0] == '.') {
      continue;
    }
    
    char perms[] = "----------";
    perms[0] = '?';
    
    mode_t mode = sbuf.st_mode;
    switch (mode & S_IFMT) {
    case S_IFREG:
      perms[0] = '-';
      break;
    case S_IFDIR:
      perms[0] = 'd';
      break;
    case S_IFLNK:
      perms[0] = 'l';
      break;
    case S_IFIFO:
      perms[0] = 'p';
      break;
    case S_IFSOCK:
      perms[0] = 's';
      break;
    case S_IFCHR:
      perms[0] = 'c';
      break;
    case S_IFBLK:
      perms[0] = 'b';
      break;
    }
    
    if (mode & S_IRUSR) {
      perms[1] = 'r';
    }
    if (mode & S_IWUSR) {
      perms[2] = 'w';
    }
    if (mode & S_IXUSR) {
      perms[3] = 'x';
    }
    
    if (mode & S_IRGRP) {
      perms[4] = 'r';
    }
    if (mode & S_IWGRP) {
      perms[5] = 'w';
    }
    if (mode & S_IXGRP) {
      perms[6] = 'x';
    }
    
    if (mode & S_IROTH) {
      perms[7] = 'r';
    }
    if (mode & S_IWOTH) {
      perms[8] = 'w';
    }
    if (mode & S_IXOTH) {
      perms[9] = 'x';
    }
    
    if (mode & S_ISUID) {
      perms[3] = (perms[3] == 'x')? 's' : 'S';
    }
    if (mode & S_ISGID) {
      perms[6] = (perms[6] == 'x')? 's' : 'S';
    }
    if (mode & S_ISVTX) {
      perms[9] = (perms[9] == 'x')? 't' : 'T';
    }

    char buf[1024] = {0};
    int off = 0;
    off += sprintf(buf, "%s ", perms);
    off += sprintf(buf+off, "%3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
    off += sprintf(buf+off, "%8lu ", (unsigned long)sbuf.st_size);
    
    const char *p_data_format = "%b %e %H:%M";
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long local_time = tv.tv_sec;
    if (sbuf.st_mtime > local_time || (local_time - sbuf.st_mtime) > 60*60*24*182) {
      p_data_format = "%b %e %Y";
    }
    
    char databuf[64] = {0};
    struct tm *p_tm = localtime(&local_time);
    strftime(databuf, sizeof(databuf), p_data_format, p_tm);
    off += sprintf(buf+off, "%s ", databuf);    
    if (S_ISLNK(sbuf.st_mode)) {
      char tmp[1024] = {0};
      readlink(dt->d_name, tmp, sizeof(tmp));
      off += sprintf(buf+off, "%s -> %s\r\n", dt->d_name, tmp);
    }
    else {
       off += sprintf(buf+off, "%s\r\n", dt->d_name);
    }
    
    printf("%s", buf);
    writen(sess->data_fd, buf, strlen(buf));
    
  }
  
  closedir(dir);
  
  return 1;
}

int port_active(session_t *sess) {
  if (sess->port != -1) {
    if (pasv_active(sess)) {
      fprintf(stderr, "both port and pasv are active");
      exit(EXIT_FAILURE);
    }
    return 1;
  }
  return 0;
}

int pasv_active(session_t *sess) {
  /*
  if (sess->pasv_listen_d != -1) {
    if (port_active(sess)) {
      fprintf(stderr, "both port and pasv are active");
      exit(EXIT_FAILURE);
    }
    return 1;
  }*/
  
  priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
  printf("sssssssssss\n");
  int active = priv_sock_get_int(sess->child_fd);
  if (active) {
    if (port_active(sess)) {
      fprintf(stderr, "both port and pasv are active");
      exit(EXIT_FAILURE);
    }
    return 1;
  }
  
  return 0;
}

int get_port_fd(session_t *sess) {
  priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
  //unsigned short port = htons(sess->port); 
  priv_sock_send_int(sess->child_fd, sess->port);
  priv_sock_send_buf(sess->child_fd, sess->ip, strlen(sess->ip));
  
  char res = priv_sock_get_result(sess->child_fd);
  if (res == PRIV_SOCK_RESULT_BAD) {
    return 0;
  }
  else if (res == PRIV_SOCK_RESULT_OK) {
    sess->data_fd = priv_sock_recv_fd(sess->child_fd);
  }
  
  return 1;
}

int get_pasv_fd(session_t *sess) {
  printf("get_pasv_fd\n");
  priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
  char res = priv_sock_get_result(sess->child_fd);
  printf("get_pasv_fd:res:%d\n", res);
  if (res == PRIV_SOCK_RESULT_BAD) {
    return 0;
  }
  else if (res == PRIV_SOCK_RESULT_OK) {
    sess->data_fd = priv_sock_recv_fd(sess->child_fd);
  }
  
  return 1;
}




int get_transfer_fd(session_t *sess) {
  printf("get_transfer_fd:port:%d\n", sess->port);
  printf("get_transfer_fd:pasv_listen_d:%d\n", sess->pasv_listen_d);
  
  if (!port_active(sess) && !pasv_active(sess)) {
    ftp_reply(sess, 425, "Use PORT or PASV first.");
    return 0;
  }
  printf("get_transfer_fd\n");
  //printf("=================%d\n", sess->data_fd );
  //sess->data_fd = inetConnect(sess->ip, sess->port, SOCK_STREAM);
  //printf("=================%d\n", sess->data_fd );
  int ret = 1;
  if (port_active(sess)) {
    printf("asdsadasdada\n");
    /*
    int clt_sock = socket(AF_INET, SOCK_STREAM, 0);   
    if(clt_sock < 0) {
      errExit("socket");
    }  
      
    struct sockaddr_in addr;   
    addr.sin_family = PF_INET;   
    addr.sin_port = htons(sess->port);   
    addr.sin_addr.s_addr = inet_addr(sess->ip);  
    
    // reset
    sess->port = -1;
    memset(sess->ip, 0, sizeof(sess->ip));
    
    
    socklen_t addr_len = sizeof(addr);  
    int connect_fd = connect(clt_sock, (struct sockaddr*)&addr, addr_len);  
    if(connect_fd < 0) {
      close(clt_sock);
      errExit("connect");
    }
    
    sess->data_fd = clt_sock;
    */
    
    if (!get_port_fd(sess)) {
      ret = 0;
    }
  }
  
  if (pasv_active(sess)) {
    /*
    int cfd = accept(sess->pasv_listen_d, NULL, NULL);
    close(sess->pasv_listen_d);
    
    if (cfd ==-1) {
      return 0;
    }
    
    sess->data_fd = cfd;*/
    
    if (get_pasv_fd(sess) == 0) {
      ret = 0;
    }
    printf("get_transfer_fd:ret:%d\n", ret);
  }
  
  sess->port = -1;
  memset(sess->ip, 0, 100);
  
  
  return ret;
}



