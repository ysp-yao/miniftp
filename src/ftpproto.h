#ifndef FTP_PROTO_H_
#define FTP_PROTO_H_

#include "session.h"


void handle_child(session_t *sess);

int list_common(void);

#endif //  FTP_PROTO_H_
