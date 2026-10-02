#ifndef NINELIVES_PROTOCOL_H
#define NINELIVES_PROTOCOL_H
void handle_client(int fd);
enum { OP_SET = 0x01, OP_GET = 0x02, OP_SNAP = 0x03, OP_RAW = 0x04, OP_QUIT = 0x05,
       OP_COMPACT = 0x06, OP_PATCH = 0x07 };
enum { ST_OK = 0x00, ST_ERR = 0x01 };
#define MAX_VAL 0x10000u
#endif
