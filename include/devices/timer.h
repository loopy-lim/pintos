#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h>

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

void timer_init(void);
void timer_calibrate(void);

int64_t timer_ticks(void);
int64_t timer_elapsed(int64_t);

void timer_sleep(int64_t ticks);
void timer_msleep(int64_t milliseconds);
void timer_usleep(int64_t microseconds);
void timer_nsleep(int64_t nanoseconds);

void timer_print_stats(void);

struct sleeping_thread {
  int64_t stand_by_time; /* Value compared to curr_time before sending to
                      ready_list */
  struct thread *thread;
  struct list_elem elem;
};

#endif /* devices/timer.h */
