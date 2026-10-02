#include <unistd.h>
int main(int argc, char **argv){ if(argc<2) return 1; setgid(1000); setuid(1000); execv(argv[1], argv+1); return 127; }
