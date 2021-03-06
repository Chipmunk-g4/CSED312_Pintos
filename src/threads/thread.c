#include "threads/thread.h"
#include "threads/fixed_point.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/*
 * MLFQS에서 nice, recent_cpu, load_avg의 default값은 0이다.
 */
#define DEFAULT_NICE 0
#define DEFAULT_RECENT_CPU 0
#define DEFAULT_LOAD_AVG 0

#define NICE_MAX 20
#define NICE_MIN -20

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of processes in Blocked state and sleeping */
static struct list sleep_list;
/* The shortest Alarm_tick which thread in sleep_list have */
int64_t next_wakeup_tick;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

// load_avg값을 저장하는 변수이다.
int load_avg;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);



/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void)
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleep_list);

  next_wakeup_tick = INT64_MAX;

  // load_avg값을 초기화한다.
  load_avg = DEFAULT_LOAD_AVG;

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void)
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t);

/*  thread_unblock 을 통해서 생성된 thread 가 ready_list 에 추가되고,
    현재 thread 와 priority 의 비교를 해주어야 한다.
 */
    if(priority > running_thread()->priority) {
//        새로 생긴 thread 의 priority 가 더 높으면, 현재 thread 가 yield 해준다.
        thread_yield();
    }

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void)
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t)
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
//  ready list 에 priority 를 비교하여 insert 한다.
  list_insert_ordered(&ready_list, &t->elem, &compare_thread_priority, NULL);
//  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void)
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void)
{
  struct thread *t = running_thread ();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void)
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void)
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread)
//  ready list 에 priority 를 비교하여 insert 한다.
      list_insert_ordered(&ready_list, &cur->elem, &compare_thread_priority, NULL);
//    list_push_back (&ready_list, &cur->elem);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority)
{
  thread_current ()->priority = new_priority;

//  TODO: change original_priority by checking priority donation

  if(!list_empty(&ready_list)) {
      struct thread * max_priority_thread = list_entry (list_front (&ready_list), struct thread, elem);
      if(new_priority < max_priority_thread->priority) {
          thread_yield();
      }
  }

}

/* Returns the current thread's priority. */
int
thread_get_priority (void)
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice /* UNUSED */ ) 
{ 
  // nice값이 범위를 넘는지 확인
  ASSERT (nice >= NICE_MIN && nice <= NICE_MAX);

  thread_current()->nice = nice;
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void)
{
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void)
{
  // load_avg값은 17.14 fixed-point 형태로 되어있기 때문에 값을 int로 변경 후 반환해야 한다.
  return fp_to_int_ro(load_avg) * 100;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void)
{
  // 스레드의 recent_cpu값은 17.14 fixed-point 형태로 되어있기 때문에 값을 int로 변경 후 반환해야 한다.
  return fp_to_int_ro(thread_current()->recent_cpu) * 100;
}

/* 입력 스레드의 priority값 계산 후 저장 */
void 
MLFQS_calc_priority(struct thread *t){

  // 입력된 스레드가 idle이면 그냥 넘긴다.
  if(t == idle_thread)
    return;

  // priority = PRI_MAX –(recent_cpu/ 4) –(nice * 2)
  int temp_priority = PRI_MAX - fp_to_int_ro(Div_fp_int( t->recent_cpu , 4 )) - t->nice * 2;

  // temp_priority의 범위가 초과하지 않도록 해서 저장
  if(temp_priority > PRI_MAX)
    t->priority = PRI_MAX;
  else if(temp_priority < PRI_MIN)
    t->priority = PRI_MIN;
  else
    t->priority = temp_priority;
}

/* 입력 스레드의 recent_cpu값 계산 후 저장 */
void 
MLFQS_calc_recent_cpu(struct thread *t){

  // 입력된 스레드가 idle이면 그냥 넘긴다.
  if(t == idle_thread)
    return;

  // recent_cpu=(2 * load_avg) / (2 * load_avg+ 1) * recent_cpu+ nice
  t->recent_cpu = Add_fp_int( Mul_fp_int(Div_fp_fp( Mul_fp_int( load_avg, 2), Add_fp_int(Mul_fp_int( load_avg, 2), 1)), t->recent_cpu), t->nice);
}

/* 현재 load_avg값 계산 후 저장 */
void 
MLFQS_calc_load_avg(void){

  // running 중인 thread가 idle인지 아닌지에 따라 ready_threads의 개수가 달라진다.
  int ready_threads;
  ready_threads = (thread_current () != idle_thread) ? list_size (&ready_list) + 1 : list_size (&ready_list);

  // load_avg= (59/60) * load_avg+ (1/60) * ready_threads
  load_avg = Add_fp_fp(Mul_fp_fp(Div_fp_int(int_to_fp(59), 60), load_avg), Mul_fp_fp(Div_fp_int(int_to_fp(1), 60), ready_threads));
}

/* 모든 스레드의 priority값 업데이트 */
void 
MLFQS_recalc(void){
  // 1. load_avg값 재계산
  MLFQS_calc_load_avg();

  // 2. 현재 존재하는 모든 thread의 priority 계산
  struct list_elem * temp;
  for (temp = list_begin(&all_list); temp != list_end(&all_list); temp = list_next(temp)){
    MLFQS_calc_recent_cpu(temp);
    MLFQS_calc_priority(temp);
  }
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux)
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;

//  initialize priority donation related variable
  t->original_priority = 0;
  t->is_donated = false;
  t->blocked_lock = NULL;
  list_init(&t->donation_list);

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void)
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();

  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void)
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/*
 * - devices/timer.c/timer_sleep 함수에서 sleep_list 등의 변수에 접근이 번거롭기 때문에 thread_sleep이라는 함수를 따로 만들어 thread.c 내에서 구현한다.
 * - thread를 재우는 역할을 하며, 그 순서는 다음과 같다.
 * 1. 인터럽트를 비활성화 시킨다.
 * 2. idle 스레드가 아닌지 확인한다.
 * 3. 입력된 ticks값으로 next_wakeup_tick 업데이트
 * 4. 현재 스레드의 wake_up_tick 업데이트
 * 5. 현재 스레드 sleep_list에 넣기
 * 6. 현재 스레드 block
 * 7. 인터럽트 다시 활성화 
 */
void
thread_sleep (int64_t ticks){
  // 1. 인터럽트 비활성화
  enum intr_level last_interrupt_status = intr_disable();
  // 자기 자신 불러오기
  struct thread *now_thread = thread_current();

  // 2. idle 스레드가 아닌지 확인하기
  if(now_thread != idle_thread){
    // 3. 입력된 ticks값으로 next_wakeup_tick 업데이트
    Update_next_wakeup_tick(ticks);
    // 4. 현재 스레드의 wake_up_tick 업데이트
    now_thread->Alarm_tick = ticks;

    // 5. 현재 스레드 sleep_list에 넣기
    list_push_back(&sleep_list, &now_thread->elem);
    // 6. 현재 스레드 block
    thread_block();
  }

  // 7. 인터럽트 다시 활성화
  intr_set_level(last_interrupt_status);

}

/*
 * - 현재 sleep_list에 들어있는 스레드 중 next_wakeup_tick 이하의 시간에 일어나야하는 모든 스레드를 깨운다.
 * - thread를 깨우는 순서는 다음과 같다.
 * 1. 인터럽트를 비활성화 시킨다.
 * 2. sleep_list를 배회한다.
 * 3. 어떤 스레드의 wake_up_tick이 현재 tick보다 작거나 같은 경우
 * 3-1. 해당 스래드를 sleep_list에서 지운다.
 * 3-2. 해당 스래드의 상태를 unblock한다.
 * 4. 이외의 경우 next_wakeup_tick을 업데이트 한다. (다음으로 작은 시간 찾기)
 * 5. 인터럽트 다시 활성화
 */
void
thread_wakeup (int64_t ticks){
  // 1. 인터럽트 비활성화
  enum intr_level last_interrupt_status = intr_disable();

  // 2. sleep_list를 배회한다.
  struct list_elem *now_elem;
  for(now_elem = list_begin(&sleep_list); now_elem != list_end(&sleep_list);){
    struct thread *now_thread = list_entry(now_elem,struct thread, elem);

    // 3. 어떤 스레드의 wake_up_tick이 현재 tick보다 작거나 같은 경우
    if(now_thread->Alarm_tick <= ticks){
      //3-1. 해당 스래드를 sleep_list에서 지운다.
      now_elem = list_remove(now_elem);
      //3-2. 해당 스래드의 상태를 unblock한다.
      thread_unblock(now_thread);
    }
    // 4. 이외의 경우 next_wakeup_tick을 업데이트 한다. (다음으로 작은 시간 찾기)
    else{
      now_elem = list_next(now_elem);
      Update_next_wakeup_tick(now_thread->Alarm_tick);
    }
  }

  // 5. 인터럽트 다시 활성화
  intr_set_level(last_interrupt_status);
}

/* 현재 next_wakeup_tick을 반환한다. */
int64_t
Get_next_wakeup_tick (void){
  return next_wakeup_tick;
}

/* next_wakeup_tick을 입력된 tick과 비교하여 알맞은 것으로 업데이트 한다. */
void
Update_next_wakeup_tick (int64_t ticks){
  if(ticks < next_wakeup_tick)
    next_wakeup_tick = ticks;
}

/* list 에서 priority 를 비교하기 위해서 사용하는 list_less_func
 * a와 b를 비교하여 a의 priority 가 더 높으면 true 를 리턴한다.
 * (list_less_func 의 주석에는 a가 작으면 true 를 리턴하라고 하였으나,
 * next_thread_to_run 에서 pop front 를 하므로 반대로 정렬을 했다)
 * */
bool
compare_thread_priority(struct list_elem* a, struct list_elem* b, void* aux) {
    struct thread * ta = list_entry(a, struct thread, elem);
    struct thread * tb = list_entry(b, struct thread, elem);

    return ta->priority > tb->priority;
}

void sort_ready_list() {
    list_sort(&ready_list, &compare_thread_priority, NULL);
}