#include "tunable.h"


int tunable_pasv_enbale = 1;
int tunable_port_enbale = 1;
unsigned int tunable_listen_port = 21;
unsigned int tunable_max_clients = 2000;
unsigned int tunable_max_peer_ip = 50;
unsigned int tunable_accept_time = 60;
unsigned int tunable_connect_timeout = 300;
unsigned int tunable_idle_session_timeout = 21;
unsigned int tunable_data_connection_timeout = 300;
unsigned int tunable_local_umask = 50;
unsigned int tunable_upload_max_rate = 50;
unsigned int tunable_download_max_rate = 50;
const char *tunable_listen_address;