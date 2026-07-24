#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) return 64;
  uid_t uid = (uid_t)strtoul(argv[1], NULL, 10); pid_t self = getpid();
  for (int pass = 0; pass < 2; pass++) {
    DIR *dir = opendir("/proc"); if (!dir) return 65; struct dirent *entry;
    while ((entry = readdir(dir))) {
      char *end; long pid = strtol(entry->d_name, &end, 10); if (*end || pid <= 1 || pid == self) continue;
      char path[128], line[256]; snprintf(path, sizeof(path), "/proc/%ld/status", pid);
      FILE *file = fopen(path, "r"); if (!file) continue; uid_t seen = (uid_t)-1;
      while (fgets(line, sizeof(line), file)) if (!strncmp(line, "Uid:", 4)) { unsigned long value; if (sscanf(line + 4, "%lu", &value) == 1) seen = (uid_t)value; break; }
      fclose(file); if (seen == uid) kill((pid_t)pid, pass ? SIGKILL : SIGTERM);
    }
    closedir(dir); sleep(1);
  }
  return 0;
}
