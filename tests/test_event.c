#include "event.h"

#include <assert.h>
#include <stdio.h>

typedef struct {
    int calls;
} test_state_t;

static void handler(const ids_event_t *event, void *user_data)
{
    test_state_t *state = (test_state_t *)user_data;

    assert(event != NULL);
    assert(event->type == IDS_EVENT_ALERT);
    state->calls++;
}

int main(void)
{
    ids_event_bus_t bus;
    ids_event_queue_t queue;
    ids_event_t event;
    ids_event_t popped;
    test_state_t state = {0};

    assert(ids_event_bus_init(&bus) == 0);
    assert(ids_event_bus_subscribe(&bus, IDS_EVENT_ALERT, handler, &state) == 0);
    event.type = IDS_EVENT_ALERT;
    event.packet = NULL;
    event.alert = NULL;
    event.alert_count = 0;
    event.message = NULL;
    ids_event_bus_publish(&bus, &event);
    assert(state.calls == 1);
    ids_event_bus_destroy(&bus);

    assert(ids_event_queue_init(&queue, 2) == 0);
    assert(ids_event_queue_push(&queue, &event));
    assert(ids_event_queue_pop(&queue, &popped));
    assert(popped.type == IDS_EVENT_ALERT);
    ids_event_queue_close(&queue);
    assert(!ids_event_queue_pop(&queue, &popped));
    ids_event_queue_destroy(&queue);

    puts("test_event: ok");
    return 0;
}
