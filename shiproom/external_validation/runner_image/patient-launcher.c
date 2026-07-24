#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) return 64;
  if (setsid() < 0 && errno != EPERM) return 65;
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return 127;
}
