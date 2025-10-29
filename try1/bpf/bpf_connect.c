// go:build ignore

#include "vmlinux.h" // Включает определения типов ядра (требует BTF)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Определение структуры для передачи данных в user-space
// Добавляем 'padding' для правильного выравнивания данных в Go
struct event {
  u32 pid;
  u8 comm[16];
  u32 daddr; // IP-адрес назначения (IPv4)
};

// Создаем "perf event array" map для отправки данных
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Это аргументы tracepoint'а sys_enter_connect
// Мы можем узнать их, посмотрев в
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
struct connect_args {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  int fd;
  struct sockaddr *uaddr; // Указатель на структуру sockaddr в user-space
  int addrlen;
};

// Прикрепляемся к tracepoint'у
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct connect_args *ctx) {

  // Получаем sockaddr от user-space
  struct sockaddr_in *addr = (struct sockaddr_in *)ctx->uaddr;

  // Проверка, что это IPv4 (AF_INET)
  // bpf_probe_read_user может завершиться ошибкой, если память недоступна
  unsigned short sin_family;
  if (bpf_probe_read_user(&sin_family, sizeof(sin_family), &addr->sin_family) !=
      0) {
    return 0; // Пропустить, если не можем прочитать
  }

  if (sin_family != AF_INET) {
    return 0; // Нас интересует только IPv4
  }

  struct event event = {};

  // 1. Получаем PID и имя процесса
  u64 id = bpf_get_current_pid_tgid();
  event.pid = id >> 32; // PID находится в старших 32 битах
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // 2. Получаем IP-адрес назначения
  // bpf_probe_read_user используется для безопасного чтения памяти user-space
  // из ядра
  bpf_probe_read_user(&event.daddr, sizeof(event.daddr),
                      &addr->sin_addr.s_addr);

  // 3. Отправляем данные в user-space через perf-буфер
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

  return 0;
}

// Обязательная лицензия для eBPF программ
char LICENSE[] SEC("license") = "GPL";
