#ifndef SG_PROTOCOL_H
#define SG_PROTOCOL_H

void handle_client(int fd);

enum {
    OP_ALLOC = 0x01, /* size(u16)            -> status, handle(1) */
    OP_FREE  = 0x02, /* handle(1)            -> status */
    OP_WRITE = 0x03, /* handle(1) len(u16) bytes(len) -> status */
    OP_READ  = 0x04, /* handle(1) len(u16)   -> status, bytes */
    OP_EXEC  = 0x05, /* len(u32) code(len)   -> (runs code) ; gated */
    OP_QUIT  = 0x06,
};

enum { ST_OK = 0x00, ST_ERR = 0x01 };

#define NHANDLE  32
#define MAX_CODE 0x1000

#endif
