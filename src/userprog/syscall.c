#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void syscall_exit (int exit_code);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

// syscall_exit 함수.
// exit code를 input으로 받아 출력해준다.
void
syscall_exit (int exit_code)
{
  struct thread * current_thread = thread_current();
  printf("%s: exit(%d)\n", current_thread->name, exit_code);
}