#pragma once
#include <chrono>
#include <csignal>
#include <signet_scan/audit.hpp>
#include <spawn.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
extern char **environ;

namespace scan_tools {
struct CommandOutcome {
  int status;
  std::string output;
};
inline CommandOutcome execute(const std::vector<std::string> &arguments) {
  if (arguments.empty())
    throw std::runtime_error("empty process command");
  std::string temporary =
      (std::filesystem::temp_directory_path() / "signet-scan-output-XXXXXX")
          .string();
  int descriptor = mkstemp(temporary.data());
  if (descriptor < 0)
    throw std::runtime_error("cannot create process output file");
  struct Cleanup {
    int descriptor;
    std::string path;
    ~Cleanup() {
      close(descriptor);
      unlink(path.c_str());
    }
  } cleanup{descriptor, temporary};
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, descriptor, STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, descriptor, STDERR_FILENO);
  posix_spawn_file_actions_addclose(&actions, descriptor);
  std::vector<char *> argv;
  for (const auto &argument : arguments)
    argv.push_back(const_cast<char *>(argument.c_str()));
  argv.push_back(nullptr);
  pid_t child = 0;
  int spawned =
      posix_spawnp(&child, argv[0], &actions, nullptr, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  if (spawned)
    throw std::runtime_error("cannot start " + arguments[0] + ": " +
                             std::to_string(spawned));
  // Every exit from the wait loop other than a completed child must still kill
  // and reap it, or the caller leaves a live process behind.
  struct Reaper {
    pid_t pending;
    ~Reaper() {
      if (!pending)
        return;
      kill(pending, SIGKILL);
      int discarded = 0;
      while (waitpid(pending, &discarded, 0) < 0 && errno == EINTR) {
      }
    }
  } reaper{child};
  int status = 0;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  for (;;) {
    auto state = waitpid(child, &status, WNOHANG);
    if (state == child) {
      reaper.pending = 0;
      break;
    }
    if (state < 0 && errno != EINTR)
      throw std::runtime_error("waitpid failed");
    if (std::chrono::steady_clock::now() > deadline)
      throw std::runtime_error("process timed out: " + arguments[0]);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  auto bytes = signet_scan::load_input(temporary, 8 * 1024 * 1024);
  return {WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status),
          std::string(bytes.begin(), bytes.end())};
}
} // namespace scan_tools
