#include <atomic>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "flags.hpp"

#if defined(ENABLE_CHRONO)
#include <chrono>
#endif

#if BUILDFLAG(IS_MACOS)
#include <cpuid.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#elif BUILDFLAG(IS_LINUX)
#include <pthread.h>
#elif BUILDFLAG(IS_WIN)
#include <Windows.h>
#endif

#if defined(ENABLE_MUTEX)
using data_type_t = uint64_t;
#elif defined(ENABLE_ATOMIC)
using data_type_t = std::atomic<uint64_t>;
#else
using data_type_t = uint64_t;
#endif

#if !defined(ENABLE_INFO_COUT)
#define DLOG(X)
#else
#define DLOG(X) std::cout << X
#endif

namespace {
constexpr auto kPrintCount = 10;

constexpr auto kDefaultCountThreads = 4;
const auto kCountThreads = std::thread::hardware_concurrency() == 0
                               ? kDefaultCountThreads
                               : std::thread::hardware_concurrency();

namespace platform_spec {
#if BUILDFLAG(IS_MACOS)
inline void set_affinity_platform(std::thread* thread, int current_core) {
  thread_affinity_policy_data_t policyData1 = {current_core};
  kern_return_t return_code = thread_policy_set(
      pthread_mach_thread_np(thread->native_handle()), THREAD_AFFINITY_POLICY,
      (thread_policy_t)&policyData1, 1);
  if (return_code != KERN_SUCCESS) {
    std::cerr << "Error calling thread_policy_set: " << return_code << "\n";
  }
}
inline auto get_current_cpu() {
  auto CPUID = [](uint32_t* INFO, int LEAF, int SUBLEAF) {
    __cpuid_count(LEAF, SUBLEAF, INFO[0], INFO[1], INFO[2], INFO[3]);
  };
  int result = -1;
  uint32_t CPUInfo[4];
  CPUID(CPUInfo, 1, 0);
  if ((CPUInfo[3] & (1 << 9)) == 0) {
    result = -1; /* no APIC on chip */
  } else {
    result = (unsigned)CPUInfo[1] >> 24;
  }
  if (result < 0) {
    result = 0;
  }
  return result;
}
#elif BUILDFLAG(IS_LINUX)
inline void set_affinity_platform(std::thread* thread, int current_core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(current_core, &cpuset);
  int return_code = pthread_setaffinity_np(thread->native_handle(),
                                           sizeof(cpu_set_t), &cpuset);
  if (return_code != 0) {
    std::cerr << "Error calling pthread_setaffinity_np: " << return_code
              << "\n";
  }
}

inline auto get_current_cpu() {
  return sched_getcpu();
}

#elif BUILDFLAG(IS_WIN)
inline void set_affinity_platform(std::thread* thread, int current_core) {
  auto return_code =
      SetThreadAffinityMask(thread->native_handle(), 1ULL << current_core);
  if (return_code == 0) {
    std::cerr << "Error calling SetThreadAffinityMask\n";
  }
}

inline auto get_current_cpu() {
  return GetCurrentProcessorNumber();
}

#endif
}  // namespace platform_spec

class Settings {
 public:
  static Settings& GetInst() {
    static Settings settings;
    return settings;
  }

  [[nodiscard]] bool IsEnableAffinity() const { return affinity_state_; }

  void EnableAffinity(bool state) { affinity_state_ = state; }

 private:
  Settings() = default;
  bool affinity_state_ = false;
};

template <typename CharT, typename... Argv>
void multiply_append(std::basic_string<CharT>* result, Argv&&... argv) {
  assert(result);
  (result->append(argv), ...);
}

[[nodiscard]] uint64_t calc(std::span<data_type_t> data, size_t current_pos) {
  if (current_pos < 2) {
    return 1;
  }
  return data[current_pos - 1] + data[current_pos - 2];
}

int print_and_return_current_cpu(size_t current_thread_num) {
  std::string result_str;
  int current_cpu = platform_spec::get_current_cpu();
  multiply_append(&result_str, "Thread #", std::to_string(current_thread_num),
                  ": on CPU ", std::to_string(current_cpu), "\n");
  DLOG(result_str);
  return current_cpu;
}
void set_affinity(std::thread* thread, size_t current_core) {
  if (!Settings::GetInst().IsEnableAffinity()) {
    return;
  }
  platform_spec::set_affinity_platform(thread, current_core);
}

void calc_offset(std::span<data_type_t> data,
                 [[maybe_unused]] std::mutex* mutex,
                 size_t current_thread_num,
                 std::vector<std::thread>* threads) {
  set_affinity(&(*threads)[current_thread_num], current_thread_num);
#if defined(ENABLE_CHRONO)
  auto now = std::chrono::high_resolution_clock::now();
  int prev_cpu = print_and_return_current_cpu(current_thread_num);
#endif
  for (size_t i = 0; i < data.size(); ++i) {
#if defined(ENABLE_MUTEX)
    std::lock_guard lock(*mutex);
    {
#endif
      data[i] = calc(data, i);
#if defined(ENABLE_MUTEX)
    }
#endif

#if defined(ENABLE_CHRONO)
    if (now + std::chrono::seconds(1) <
        std::chrono::high_resolution_clock::now()) {
      now += std::chrono::seconds(1);
      auto current_cpu = print_and_return_current_cpu(current_thread_num);
      if (prev_cpu != current_cpu) {
        prev_cpu = current_cpu;
        DLOG("SWITCH CPU CONTEXT\n");
      }
    }
#endif
  }

  print_and_return_current_cpu(current_thread_num);
}

[[maybe_unused]] void summary_data(std::span<data_type_t> data,
                                   [[maybe_unused]] std::mutex* mutex,
                                   size_t current_thread_num,
                                   std::vector<std::thread>* threads) {
  set_affinity(&(*threads)[current_thread_num], current_thread_num);

  uint64_t result = 0;
  for (size_t i = 3; i < data.size(); ++i) {
#if defined(ENABLE_MUTEX)
    std::lock_guard lock(*mutex);
#endif
    if (data[i] == 0) {
      --i;
      continue;
    }
    result += data[i];
  }

  std::string result_string;
  multiply_append(&result_string,
                  "finish read thread, result = ", std::to_string(result),
                  "\n");
  DLOG(result_string);
}

[[maybe_unused]] void summary_data_not_thread_safe(
    std::span<data_type_t> data) {
  uint64_t result = 0;
  for (size_t i = 3; i < data.size(); ++i) {
    result += data[i];
  }

  std::string result_string;
  multiply_append(&result_string,
                  "finish read thread, result = ", std::to_string(result),
                  "\n");
  DLOG(result_string);
}

}  // namespace

int main(int argc, char* argv[]) {
  constexpr std::string_view kAffinityParam = "affinity";
  Settings::GetInst().EnableAffinity(argc > 1 && kAffinityParam == argv[1]);

  const unsigned int kCount{10'000'000 * kCountThreads};

  auto data = std::make_unique<data_type_t[]>(kCount);

  std::vector<std::mutex> mutexes(kCountThreads);

  std::vector<std::thread> write_threads;
  write_threads.reserve(kCountThreads);

#if defined(ENABLE_MUTEX) || defined(ENABLE_ATOMIC)
  std::vector<std::thread> read_threads;
  read_threads.reserve(kCountThreads);
#endif

  const auto count_for_thread = kCount / kCountThreads;
#if defined(ENABLE_MAIN_THREAD_WORK)
  for (size_t i = 1; i < kCountThreads; ++i) {
#else
  for (size_t i = 0; i < kCountThreads; ++i) {
#endif
    write_threads.emplace_back(
        &calc_offset,
        std::span(data.get() + count_for_thread * i, count_for_thread),
        &mutexes[i], i, &write_threads);
#if defined(ENABLE_MUTEX) || defined(ENABLE_ATOMIC)
    read_threads.emplace_back(
        &summary_data,
        std::span(data.get() + count_for_thread * i, count_for_thread),
        &mutexes[i], i, &read_threads);
#endif
  }
#if defined(ENABLE_MAIN_THREAD_WORK)
  calc_offset(std::span(data.get(), count_for_thread), &mutexes[0], 0,
              &write_threads);
#endif
  for (auto& thread : write_threads) {
    thread.join();
  }

#if defined(ENABLE_MUTEX) || defined(ENABLE_ATOMIC)
  for (auto& thread : read_threads) {
    thread.join();
  }
#else
  for (size_t i = 0; i < kCountThreads; ++i) {
    summary_data_not_thread_safe(
        std::span(data.get() + count_for_thread * i, count_for_thread));
  }
#endif

  for (size_t num_thread = 0; num_thread < kCountThreads; ++num_thread) {
    for (size_t i = 0 + count_for_thread * num_thread;
         i < count_for_thread * num_thread + kPrintCount; ++i) {
      std::cout << data[i] << ' ';
    }
    std::cout << std::endl;
  }
  return 0;
}
