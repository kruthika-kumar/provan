#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) return 64;
  pid_t child = fork();
  if (child < 0) return 65;
  if (child == 0) {
    if (setsid() < 0) _exit(66);
    execvp(argv[1], &argv[1]);
    perror("execvp");
    _exit(127);
  }
  int status;
  if (waitpid(child, &status, 0) < 0) return 67;
  /* The child is the dedicated session/process-group leader.  Background
     descendants cannot continue changing /output after its main command exits. */
  kill(-child, SIGTERM);
  struct timespec grace = { .tv_sec = 0, .tv_nsec = 250000000 };
  nanosleep(&grace, NULL);
  kill(-child, SIGKILL);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 1);
}
