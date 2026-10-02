#ifndef CC_PROTOCOL_H
#define CC_PROTOCOL_H
void handle_client(int fd);
enum { OP_ADD = 0x01, OP_DEL = 0x02, OP_VIEW = 0x03, OP_EDIT = 0x04,
       OP_HANDLER = 0x05, OP_CALL = 0x06, OP_QUIT = 0x07 };
enum { ST_OK = 0x00, ST_ERR = 0x01 };
#endif
