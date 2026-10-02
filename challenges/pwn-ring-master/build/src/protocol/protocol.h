#ifndef RM_PROTOCOL_H
#define RM_PROTOCOL_H
void handle_client(int fd);
enum { OP_QUIT = 0x00, OP_CREATE = 0x01, OP_PUB = 0x02, OP_RESIZE = 0x03,
       OP_READ = 0x04, OP_DESTROY = 0x05, OP_DELIVER = 0x06 };
enum { ST_OK = 0x00, ST_ERR = 0x01 };
#endif
