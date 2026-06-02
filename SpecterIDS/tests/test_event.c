#include "event.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int calls;
} test_state_t;

static void handler(const ids_event_t *event, void *user_data)
{
    test_state_t *state = (test_state_t *)user_data;

    assert(event != NULL);
    assert(event->type == IDS_EVENT_ALERT);
    assert(event->event_id > 0);
    assert(strlen(event->uuid) == 36);
    assert(event->monotonic_timestamp_ns > 0);
    if (event->alert != NULL) {
        assert(strcmp(event->alert->source_ip, "192.0.2.1") == 0);
        assert(strcmp(event->source_metadata, "192.0.2.1") == 0);
    }
    state->calls++;
}

int main(void)
{
    ids_event_bus_t bus;
    ids_event_bus_snapshot_t snapshot;
    ids_event_queue_t queue;
    ids_event_t event;
    ids_event_t low_event;
    ids_event_t high_event;
    ids_event_t popped;
    alert_t alert;
    test_state_t state = {0};

    memset(&event, 0, sizeof(event));
    memset(&alert, 0, sizeof(alert));
    snprintf(alert.source_ip, sizeof(alert.source_ip), "192.0.2.1");
    event.type = IDS_EVENT_ALERT;
    event.alert = &alert;
    event.alert_count = 1;
    event.message = "alert-ready";

    assert(ids_event_bus_init(&bus) == 0);
    assert(ids_event_bus_subscribe(&bus, IDS_EVENT_ALERT, handler, &state) == 0);
    ids_event_bus_publish(&bus, &event);
    assert(state.calls == 1);
    ids_event_bus_snapshot(&bus, &snapshot);
    assert(snapshot.published_events == 1);
    assert(snapshot.dispatched_events == 1);
    assert(snapshot.dropped_events == 0);
    ids_event_bus_destroy(&bus);

    state.calls = 0;
    assert(ids_event_bus_init(&bus) == 0);
    assert(ids_event_bus_subscribe(&bus, IDS_EVENT_ALERT, handler, &state) == 0);
    assert(ids_event_bus_start_async(&bus, 8) == 0);
    ids_event_bus_publish(&bus, &event);
    ids_event_bus_stop_async(&bus);
    assert(state.calls == 1);
    ids_event_bus_snapshot(&bus, &snapshot);
    assert(snapshot.published_events == 1);
    assert(snapshot.dispatched_events == 1);
    ids_event_bus_destroy(&bus);

    assert(ids_event_queue_init(&queue, 2) == 0);
    low_event = event;
    high_event = event;
    low_event.priority = IDS_EVENT_PRIORITY_LOW;
    high_event.priority = IDS_EVENT_PRIORITY_CRITICAL;
    high_event.alert_count = 99;
    assert(ids_event_queue_push(&queue, &low_event));
    assert(ids_event_queue_push(&queue, &high_event));
    assert(ids_event_queue_pop(&queue, &popped));
    assert(popped.type == IDS_EVENT_ALERT);
    assert(popped.alert_count == 99);
    assert(popped.uuid[0] == '\0' || strlen(popped.uuid) < IDS_EVENT_UUID_LEN);
    assert(ids_event_queue_pop(&queue, &popped));
    assert(popped.alert_count == 1);
    ids_event_queue_close(&queue);
    assert(!ids_event_queue_pop(&queue, &popped));
    ids_event_queue_destroy(&queue);

    puts("test_event: ok");
    return 0;
}
