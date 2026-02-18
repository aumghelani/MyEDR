/*
    A simple fixed-size circular queue of EDR_EVENT records.

    Callbacks run at various IRQLs and in arbitrary thread contexts, so every
    access to the queue is guarded by a spin lock. We keep the events by value
    (no embedded pointers) so there is nothing to free on dequeue and no
    lifetime puzzle across the kernel/user boundary.

    Overflow policy: if the queue is full we drop the newest event. Dropping is
    preferable to blocking inside a callback that may run at DISPATCH_LEVEL.
*/

#pragma once

#include <ntddk.h>
#include "Driver.h"

#define EDR_QUEUE_CAPACITY 512

typedef struct _EDR_EVENT_QUEUE {
    EDR_EVENT   items[EDR_QUEUE_CAPACITY];
    ULONG       head;     // index of the oldest event
    ULONG       count;    // number of valid events
    ULONG       dropped;  // diagnostic counter
    KSPIN_LOCK  lock;
} EDR_EVENT_QUEUE, *PEDR_EVENT_QUEUE;

__forceinline void EdrQueueInit(PEDR_EVENT_QUEUE q) {
    RtlZeroMemory(q, sizeof(*q));
    KeInitializeSpinLock(&q->lock);
}

// Push one event. Returns FALSE if the queue was full (event dropped).
__forceinline BOOLEAN EdrQueuePush(PEDR_EVENT_QUEUE q, const EDR_EVENT* ev) {
    KIRQL oldIrql;
    BOOLEAN ok = FALSE;

    KeAcquireSpinLock(&q->lock, &oldIrql);
    if (q->count < EDR_QUEUE_CAPACITY) {
        ULONG tail = (q->head + q->count) % EDR_QUEUE_CAPACITY;
        q->items[tail] = *ev;
        q->count++;
        ok = TRUE;
    } else {
        q->dropped++;
    }
    KeReleaseSpinLock(&q->lock, oldIrql);
    return ok;
}

// Pop the oldest event into *out. Returns FALSE if the queue was empty.
__forceinline BOOLEAN EdrQueuePop(PEDR_EVENT_QUEUE q, EDR_EVENT* out) {
    KIRQL oldIrql;
    BOOLEAN ok = FALSE;

    KeAcquireSpinLock(&q->lock, &oldIrql);
    if (q->count > 0) {
        *out = q->items[q->head];
        q->head = (q->head + 1) % EDR_QUEUE_CAPACITY;
        q->count--;
        ok = TRUE;
    }
    KeReleaseSpinLock(&q->lock, oldIrql);
    return ok;
}
