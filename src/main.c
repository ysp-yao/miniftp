#include "tlpi_hdr.h"
#include "inet_sockets.h"

int main(int argc, char *argv[]) {

  if (getuid() != 0) {
    errExit("miniftpd must be started as root");  
  }


  return 0;
}
