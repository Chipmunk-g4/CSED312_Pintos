/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void
sema_down (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  while (sema->value == 0) 
    {
      // list_push_back (&sema->waiters, &thread_current ()->elem);

      /* 
       * semaphore의 waiters 리스트에 스레드가 입력될 때 
       * 스레드의 priority에 따라 정렬되어 입력 되도록 한다.
       */
      list_insert_ordered(&sema->waiters, &thread_current ()->elem, 
                                        (list_less_func *)compare_thread_priority, NULL);
      thread_block ();
    }
  sema->value--;
  intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) 
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (sema->value > 0) 
    {
      sema->value--;
      success = true; 
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) 
{
  enum intr_level old_level;

  ASSERT (sema != NULL);

  old_level = intr_disable ();
  if (!list_empty (&sema->waiters)){
    /*
     * 스레드를 unblock하기 전 semaphore의 waiters리스트를 한번 정렬해준 다음에 
     * 가장 앞에있는 스레드를 unblock한다.
     */
    list_sort (&sema->waiters, (list_less_func *)compare_thread_priority, NULL);
    thread_unblock (list_entry (list_pop_front (&sema->waiters),
                                struct thread, elem));
  }
  sema->value++;
  intr_set_level (old_level);

  // 이 후 yield를 하여 priority가 가장 높은 스레드가 실행될 수 있도록 한다.
  thread_yield();
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) 
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) 
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) 
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));

  /*
   * lock_acquire할 때 다음 두가지 상황으로 나눌 수 있다.
   * 1. lock의 holder가 존재하지 않는 경우. 즉, lock을 가져올 수 있는 경우
   * 2. lock의 holder가 이미 존재하는 경우. 즉, lock을 가져올 수 없는 경우
   * 
   * 이때 1인 경우 바로 현재 스레드를 lock holder로 임명하고 세마포어를 낮추면 된다.
   * 하지만 2인 경우 아래의 과정을 수행해야 한다.
   * 
   * 1. 현재 스레드가 lock을 기다리고 있음을 저장한다. (blocked_lock)
   * 2. lock의 holder의 donation list 즉, 대기줄에 현재 스레드를 넣는다.
   * 3. 현재 스레드를 now_thread라는 변수에 넣는다.
   * 4. holder 스레드의 priority가 now_thread의 priority 값보다 작으면 holder 스레드의 priority를 now_thread의 priority 값으로 설정하여 priority donate를 한다.
   * 5. 그리고 해당 holder의 blocked_lock의 holder를 now_thread에 넣는다. (이는 nested donation을 수행하기 위함이다.)
   * 6. 4~5 과정을 now_thread가 null 즉, nested donation이 끝날 때 까지 반복한다.
   * 
   * 위 과정을 수행한 다음 스레드는 자신의 차례가 되면 lock을 가져오게 된다.
   * (이 가져오는 과정은 lock_release에 의해 수행된다.)
   * 
   * 그리고 1~6 과정이 길고 복잡하기 때문에 새로운 함수를 선언하여 해당 함수 내에서 수행되도록 한다.
   * (void donate_priority_with_nested(struct lock *l))
   * 
   * 이후 만약 holder가 있는 경우라면 sema_down을 통해 여기서 block되어 lock이 release될 때 까지 기다리게 된다.
   */
  enum intr_level old_level = intr_disable (); // 인터럽트 해제

  if(lock->holder != NULL){
    donate_priority_with_nested(lock); // priority donation하기
  }
  else
    thread_current()->locker = NULL; // locker가 없으므로 null로 만든다.

  sema_down (&lock->semaphore);
  lock->holder = thread_current ();

  intr_set_level (old_level); // 인터럽트 활성화
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) 
{
  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));

  /*
   * lock_release는 크게 다음 2개의 순서대로 진행된다.
   * 1. lock->holder를 삭제하고 세마포어를 증가시킨다. (이때 donation_list에서 lock을 기다리던 스레드 중 가장 높은 priority를 가진 스레드가 unblock된다.)
   * 2. lock을 기다리던 스레드들을 unblock 및 donation_list에서 지운다. 즉, 해방시킨다.
   * 3. 현재 스레드의 priority를 결정한다.
   * 
   * 여기서 현재 스레드와 lock->holder는 동일하여야 한다.
   * 
   * 이때 2, 3번의 수행에 대해서 더 자세하게 설명하면 다음과 같다.
   * 2. 
   *  + 1. 현재 스레드의 donation이 비어있지 않은지 확인. (만약 비어있는 경우에는 2번을 넘긴다.)
   *  + 2. donation_list를 순회하면서 다음을 수행한다.
   *    + 2-1. 현재 elem의 thread의 blocked_lock이 lock과 같은 경우 (같지 않으면 다음 elem으로 넘어간다.)
   *    + 2-2. 해당 elem을 donation_list에서 제거한 다음, blocked_lock을 NULL로 만든다.
   * 3.
   *  + 1-1. 만약 2.를 수행한 이후에도 donation_list가 비어있지 않은 경우 (이러한 경우에는 lock이외의 다른 lock을 기다리는 multiple donation 상황이다.)
   *    + 1-1-1. donation_list에서 priority가 가장 큰 스레드의 priority값을 가져온다.
   *    + 1-1-2. 만약 현재 스레드의 original_priority가 1-1-1에서 구한 값보다 크면
   *             thread_set_priority(thread_current()->original_priority);를 수행한다.
   *    + 1-1-3. 만약 같거나 작으면
   *             현재 스레드의 priority를 priority가 가장 큰 스레드의 priority값으로 직접 설정한 후 thread_yield()를 수행한다. 
   *             (가장 큰 값을 가지고 있어야 lock을 수행한 뒤 donation을 해제할 수 있다.)
   *             (thread_yield를 수행하는 이유는 해당 lock과 관련 없으면서 priority가 더 큰 스레드를 먼저 끝낸 후 donation을 마치기 위함이다.)
   *  + 1-2. 만약 donation_list가 비어있는 경우
   *          thread_set_priority(thread_current()->original_priority);를 수행한다.
   * 
   */

  enum intr_level old_level = intr_disable (); // 인터럽트 해제

  // 1. lock->holder를 삭제하고 세마포어를 증가시킨다.
  lock->holder = NULL;

  // 2. lock을 기다리던 스레드들을 unblock 및 donation_list에서 지운다. 즉, 해방시킨다.
  // + 1. 현재 스레드의 donation이 비어있지 않은지 확인. (만약 비어있는 경우에는 2번을 넘긴다.)
  if(!list_empty(&thread_current()->donation_list)){
    struct list_elem *temp;
    // + 2. donation_list를 순회하면서 다음을 수행한다.
    for (temp = list_begin (&thread_current()->donation_list); temp != list_end (&thread_current()->donation_list); temp = list_next (temp)){
      // + 2-1. 현재 elem의 thread의 blocked_lock이 lock과 같은 경우 (같지 않으면 다음 elem으로 넘어간다.)
      struct thread *temp_thd = list_entry (temp, struct thread, donation_elem);
      if(temp_thd->blocked_lock == lock){
        // + 2-2. 해당 elem을 donation_list에서 제거한 다음, blocked_lock을 NULL로 만든다.
        list_remove(temp);
        temp_thd->blocked_lock = NULL;
      }
    }
  }

  struct thread *t = thread_current();
  t->priority = t->original_priority;

  if(!list_empty(&t->donation_list)){
    int largest_priority = list_entry(list_max(&t->donation_list, (list_less_func *)compare_thread_priority, NULL), struct thread, donation_elem)->priority;
    if(largest_priority > t->priority)
      t->priority = largest_priority;
  }

  sema_up (&lock->semaphore);

  /*
  // 3. 현재 스레드의 priority를 결정한다.
  // + 1-1. 만약 2.를 수행한 이후에도 donation_list가 비어있지 않은 경우 (이러한 경우에는 lock이외의 다른 lock을 기다리는 multiple donation 상황이다.)
  if(!list_empty(&thread_current()->donation_list)){
    // + 1-1-1. donation_list에서 priority가 가장 큰 스레드의 priority값을 가져온다.
    int largest_priority = list_entry(list_max(&thread_current()->donation_list, (list_less_func *)compare_thread_priority, NULL), struct thread, donation_elem)->priority;
    // + 1-1-2. 만약 현재 스레드의 original_priority가 1-1-1에서 구한 값보다 크면
    //            thread_set_priority(thread_current()->original_priority);를 수행한다.
    if(thread_current()->original_priority > largest_priority){
      thread_set_priority(thread_current()->original_priority);
    }
    // + 1-1-3. 만약 같거나 작으면
    //           현재 스레드의 priority를 priority가 가장 큰 스레드의 priority값으로 직접 설정한 후 thread_yield()를 수행한다. 
    //           (가장 큰 값을 가지고 있어야 lock을 수행한 뒤 donation을 해제할 수 있다.)
    //           (thread_yield를 수행하는 이유는 해당 lock과 관련 없으면서 priority가 더 큰 스레드를 먼저 끝낸 후 donation을 마치기 위함이다.)
    else {
      thread_current()->priority = largest_priority;
      thread_yield();
    }
  }
  // + 1-2. 만약 donation_list가 비어있는 경우
  //         thread_set_priority(thread_current()->original_priority);를 수행한다.
  else{
    thread_set_priority(thread_current()->original_priority);
  }
  */

  intr_set_level (old_level); // 인터럽트 활성화
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) 
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem 
  {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
  };

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) 
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  
  sema_init (&waiter.semaphore, 0);
  list_push_back (&cond->waiters, &waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  if (!list_empty (&cond->waiters)){
    /*
     * conditional variable의 waiters 리스트에서 세마포어를 가져오기 전
     * 세마포어의 가장 앞에있는 스레드의 priority 순서대로 세마포어가 나올 수 있도록 
     * waiters 리스트를 정렬한다.
     */
    list_sort (&cond->waiters, (list_less_func *)cmp_sem_front_priority, NULL);
    sema_up (&list_entry (list_pop_front (&cond->waiters),
                          struct semaphore_elem, elem)->semaphore);
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) 
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}

bool cmp_sem_front_priority(struct list_elem *a, struct list_elem *b, void *aux)
{
  // semaphore_elem 형식으로 a, b 변환
  struct semaphore_elem *sema = list_entry (a, struct semaphore_elem, elem);
  struct semaphore_elem *semb = list_entry (b, struct semaphore_elem, elem);
 
  // 각 세마포어의 waiters 리스트의 front에 있는 thread의 priority가 
  // sema가 더 크면 true, semb가 더 크면 false를 반환한다.
  return list_entry(list_front(&sema->semaphore.waiters), struct thread, elem)->priority > list_entry (list_front(&semb->semaphore.waiters), struct thread, elem)->priority;
}

/*
   * 아래의 함수는 아래의 6가지의 과정을 수행하는 함수이다.
   * 
   * 1. 현재 스레드가 lock을 기다리고 있음을 저장한다. (blocked_lock)
   * 2. lock의 holder의 donation list 즉, 대기줄에 현재 스레드를 넣는다.
   * 3. 현재 스레드를 now_thread라는 변수에 넣는다.
   * 4. holder 스레드의 priority가 now_thread의 priority 값보다 작으면 holder 스레드의 priority를 now_thread의 priority 값으로 설정하여 priority donate를 한다.
   * 5. 그리고 해당 holder의 blocked_lock의 holder를 now_thread에 넣는다. (이는 nested donation을 수행하기 위함이다.)
   * 6. 4~5 과정을 now_thread의 blocked_lock의 holer(즉, locker)가 null 즉, nested donation이 끝날 때 까지 반복한다.
   */
void donate_priority_with_nested(struct lock *l){

  // 현재 스레드의 locker를 l의 holder로 설정
  thread_current()->locker = l->holder;
  // 1. 현재 스레드가 lock을 기다리고 있음을 저장한다. (blocked_lock)
  thread_current()->blocked_lock = l;
  // 2. lock의 holder의 donation list 즉, 대기줄에 현재 스레드를 넣는다.
  list_push_front(&l->holder->donation_list, &thread_current()->donation_elem);

  // 3. 현재 스레드를 now_thread라는 변수에 넣는다.
  struct thread *now_thread = thread_current();

  while(now_thread->locker!=NULL){
    // 4. holder 스레드의 priority가 now_thread의 priority 값보다 작으면 holder 스레드의 priority를 now_thread의 priority 값으로 설정하여 priority donate를 한다.
    if(now_thread->priority > now_thread->locker->priority){
      now_thread->locker->priority = now_thread->priority;
      // 5. 그리고 해당 holder의 blocked_lock의 holder를 now_thread에 넣는다. (이는 nested donation을 수행하기 위함이다.)
      now_thread = now_thread->locker;
    }
  }
  // 6. 4~5 과정을 now_thread의 blocked_lock의 holer(즉, locker)가 null 즉, nested donation이 끝날 때 까지 반복한다.
}