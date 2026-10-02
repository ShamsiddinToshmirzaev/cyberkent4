#include "../protocol/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

static void reap(int s) { (void)s; while (waitpid(-1, NULL, WNOHANG) > 0); }

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 1337;
    signal(SIGCHLD, reap);
    signal(SIGPIPE, SIG_IGN);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(s, 64) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "verifier-ex listening on :%d\n", port);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        pid_t pid = fork();
        if (pid == 0) {
            close(s);
            dup2(c, 0);
            dup2(c, 1);
            handle_client(c);
            _exit(0);
        }
        close(c);
    }
}
