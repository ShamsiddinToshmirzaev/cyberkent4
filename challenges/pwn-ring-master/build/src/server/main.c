#include "../protocol/protocol.h"
#include "../ring/ring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

static void *worker(void *arg)
{
    int c = (int)(long)arg;
    handle_client(c);
    close(c);
    return NULL;
}

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 1337;
    signal(SIGPIPE, SIG_IGN);
    rm_init();

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    if (listen(s, 64) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "ring-master listening on :%d\n", port);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        pthread_t t;
        if (pthread_create(&t, NULL, worker, (void *)(long)c) != 0) {
            close(c);
            continue;
        }
        pthread_detach(t);
    }
}
