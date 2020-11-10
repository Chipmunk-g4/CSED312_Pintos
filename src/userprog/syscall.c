#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void check_valid_address(void *address);
void get_argument(int *esp, int *arg, int count);

void syscall_halt (void);
void syscall_exit (int exit_code);
tid_t syscall_exec(const char *cmd_line);
int syscall_wait (tid_t pid);
bool syscall_create (const char *file , unsigned initial_size);
bool syscall_remove (const char *file);
int syscall_read(int fd, void *buffer, unsigned size);
int syscall_write(int fd, const void *buffer, unsigned size);

// 아직까지 모든 syscall은 임시적인 단계로 계속 수정이 필요하다.

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int arg[4]; // argument를 저장하는 공간이다.
  
  //printf("number: %d\n", *(int *)(f->esp));
  //hex_dump(f->esp, f->esp, 100, 1);

  switch (*(int *)(f->esp)) { // f->esp에는 syscall number가 담겨있다.
    case SYS_HALT:
      syscall_halt();
      break;
    case SYS_EXIT:
      get_argument(f->esp, arg, 1); // 인자: 1개
      syscall_exit(arg[0]);
      break;
    case SYS_EXEC:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f -> eax = syscall_exec(arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_WAIT:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_wait(arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_CREATE:
      get_argument(f->esp, arg, 2); // 인자: 2개
      f->eax = syscall_create((const char *) arg[0], arg[1]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_REMOVE:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_remove((const char *) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      get_argument(f->esp, arg, 3); // 인자: 3개
      f->eax = syscall_read(arg[0],arg[1],arg[2]);
      break;
    case SYS_WRITE:
      get_argument(f->esp, arg, 3); // 인자: 3개
      f->eax = syscall_write(arg[0],arg[1],arg[2]);
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    default:
      // 유효하지 않은 syscall
      syscall_exit(-1);
  }
}

// 1. 작동의 오류를 검사하는 함수들   --------------------

// 입력되는 주소가 유효한지 검사한다.
void check_valid_address(void *address){
  // address가 0x08048000~0xc0000000 사이 (유저영역)에 있는지 검사한다.
  if(!(0xc0000000UL >= address && address >= (void *)0x08048000UL)){
    // 올바른 주소가 아니므로 프로세스를 종료시킨다.
    syscall_exit(-1);
  }
}

// 2. 작동에 도움을 주는 함수들   ------------------------

// 유저스택에 있는 데이터를 esp에서 4byte크기로 count개수 만큼 가져온다.
void get_argument(int *esp, int *arg, int count){

  // every count
  while (count--)
  {
    esp++;

    // check whether bound of esp is legal
    check_valid_address (esp);
    check_valid_address (esp+3);

    // get value
    *(arg++) = *esp;
  }
}

// 3. Syscall 함수들            -------------------------

// halt 시스템 콜
void syscall_halt (void){
  // 핀토스를 종료시킨다.
  shutdown_power_off();
}

// syscall_exit 함수.
// exit code를 input으로 받아 출력해준다.
void
syscall_exit (int exit_code)
{
  struct thread * current_thread = thread_current();
  printf("%s: exit(%d)\n", current_thread->name, exit_code);
  thread_exit ();
}

// exec 시스템 콜
tid_t syscall_exec(const char *cmd_line){
  return process_execute(cmd_line);
}

// wait 시스템 콜
int syscall_wait (tid_t pid){
  return process_wait(pid);
}

// create 시스템 콜
bool syscall_create (const char *file , unsigned initial_size){
  // 파일을 생성한다.
  return filesys_create (file, initial_size);
}

// remove 시스템 콜
bool syscall_remove (const char *file){
  // 파일을 삭제한다.
  return filesys_remove (file);
}

// read 시스템 콜
int syscall_read(int fd, void *buffer, unsigned size){
  int i;
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
  }

  return i;
}

int syscall_write(int fd, const void *buffer, unsigned size){
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}