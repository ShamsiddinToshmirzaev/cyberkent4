#include "protocol.h"
#include "../session/session.h"

void handle_client(int fd)
{
    session(fd);
}
