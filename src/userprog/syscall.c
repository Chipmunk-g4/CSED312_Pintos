#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);

void check_valid_address(void *address);
void get_argument(int *esp, int *arg, int count);

void syscall_halt (void);
void syscall_exit (int exit_code);
tid_t syscall_exec(const char *cmd_line);
int syscall_wait (tid_t pid);
bool syscall_create (const char *file , unsigned initial_size);
bool syscall_remove (const char *file);
int syscall_open (const char* file);
int syscall_filesize(int fd);
int syscall_read(int fd, void *buffer, unsigned size);
int syscall_write(int fd, const void *buffer, unsigned size);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);
void syscall_close (int fd);

void check_addr_user(void *addr);
// 아직까지 모든 syscall은 임시적인 단계로 계속 수정이 필요하다.

// lock for one by one access
struct lock locking_file;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // initial setting lock
  lock_init(&locking_file);
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
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_open((const char *) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_FILESIZE:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_filesize((int) arg[0]); // 계산 후 결과를 eax에 저장
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
      get_argument(f->esp, arg, 2); // 인자: 2개
      syscall_seek((int)arg[0], (unsigned)arg[1]);
      break;
    case SYS_TELL:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_tell((int) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_CLOSE:
      get_argument(f->esp, arg, 1); // 인자: 1개
      syscall_close((int) arg[0]);
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
  if (!(is_user_vaddr (address) && address >= (void *)0x08048000UL)){
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

    check_addr_user(esp);
    check_addr_user(esp+3);

    // get value
    *(arg++) = *esp;
  }
}

// check address is in user memory or not
// if not then call system call exit with -1
void check_addr_user(void *addr) {
  if (!is_user_vaddr(addr))
    syscall_exit(-1);
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
  thread_current()->exit_code = exit_code;
  printf("%s: exit(%d)\n", current_thread->name, exit_code);
  thread_exit ();
}

// exec 시스템 콜
tid_t syscall_exec(const char *cmd_line){

  tid_t tid;
  struct thread *child;

  tid = process_execute (cmd_line);
  child = thread_get_child (tid);

  sema_down (&child->load_sema);

  // if no file, return error
  if(!child->load_complete) return -1;

  return tid;
}

// wait 시스템 콜
int syscall_wait (tid_t pid){
  return process_wait(pid);
}

// create 시스템 콜
bool syscall_create (const char *file , unsigned initial_size){
  // we don't accept NULL file
  if (file == NULL) {syscall_exit(-1);}
  // 파일을 생성한다.
  return filesys_create (file, initial_size);
}

// remove 시스템 콜
bool syscall_remove (const char *file){
  // we don't accept NULL file
  if (file == NULL) {syscall_exit(-1);}
  // 파일을 삭제한다.
  return filesys_remove (file);
}

// open 시스템 콜
int syscall_open (const char* file){
  int result;

  lock_acquire(&locking_file); //lock on

  // we don't accept NULL file
  if (file == NULL) {syscall_exit(-1);}

  // 미리 만들어둔 process_add_file함수를 사용하여 파일을 프로세스에 추가한다.
  result = process_add_file (filesys_open (file), file);

  lock_release(&locking_file); // lock off
  return result;
}

// filesize 시스템 콜
int syscall_filesize(int fd){
  // 미리 만들어둔 함수로 파일을 프로세스에서 가져온다.
  struct file *tmp = process_get_file (fd);

  // 만약 비어있는 경우 -1을 반환한다. 그렇지 않으면 파일 길이를 반환한다.
  return (tmp == NULL) ? -1 : file_length(tmp);
}

// read 시스템 콜
int syscall_read(int fd, void *buffer, unsigned size){
  int i;
  int result;

  // if buffer out of border exit(-1)
  check_valid_address(buffer);

  lock_acquire(&locking_file); //lock on

  // STDIN인 경우 키보드로부터 값을 입력받는다.
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
    result = i; // 입력받은 바이트 수 반환
  }
  else if(fd >= 2){ // 그 외의 경우
    // fd 자리에 파일이 없는 경우
    if(process_get_file (fd) == NULL){
      lock_release(&locking_file); // lock off
      syscall_exit(-1); // 실패시 -1 반환
    }
    // 파일이 있는 경우
    else{ 
      size = file_read (process_get_file (fd), buffer, size);
      result = size;// 데이터를 입력받고 size를 반환한다.
    }
  }

  lock_release(&locking_file); // lock off
  return result;
}

// write 시스템 콜
int syscall_write(int fd, const void *buffer, unsigned size){
  int result;

  // if buffer out of border exit(-1)
  check_valid_address(buffer);

  lock_acquire(&locking_file); //lock on

  // STDOUT인 경우 화면에 출력
  if (fd == 1) {
    putbuf(buffer, size);
    result = size;
  }
  else if(fd >= 2){ // fd값이 2 이상인 경우 
    // fd 자리에 파일이 없는 경우
    if(process_get_file (fd) == NULL){
      lock_release(&locking_file); // lock off
      syscall_exit(-1); // 실패시 -1 반환
    }
    // fd의 deny_write가 1인 경우, 
    // file_deny_write함수를 통해 파일을 잠궈 접근을 못하게 막는다.
    if (process_get_file(fd)->deny_write) {
        file_deny_write(thread_current()->fd[fd]);
    }

    // 파일이 있는 경우
    size = file_write (process_get_file (fd), buffer, size);
    result = size;// 데이터를 기록하고 size를 반환한다.
  }
  lock_release(&locking_file); // lock off
  return result;
}

// seek 시스템 콜
void syscall_seek (int fd, unsigned position){
  struct file *tmp = process_get_file (fd);
  // 파일이 비어있으면 무시
  if (tmp == NULL) return;

  // 파일 offset 변경
  file_seek (tmp, position);  
}

unsigned syscall_tell (int fd){
  struct file *tmp = process_get_file (fd);
  // 파일이 비어있으면 -1 반환
  if (tmp == NULL) return -1;

  // 파일의 offset 반환
  return file_tell (tmp);
}

// close 시스템 콜
void syscall_close (int fd){
  // 미리 구현한 함수를 통해 파일을 닫는다.
  process_close_file (fd);
}