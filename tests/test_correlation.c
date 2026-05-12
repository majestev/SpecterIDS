#include "correlation.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static alert_t make_alert(alert_type_t type, time_t seconds)
{
    alert_t alert;

    memset(&alert, 0, sizeof(alert));
    alert.type = type;
    alert.severity = IDS_SEVERITY_HIGH;
    snprintf(alert.source_ip, sizeof(alert.source_ip), "198.51.100.77");
    snprintf(alert.destination_ip, sizeof(alert.destination_ip), "192.0.2.10");
    alert.timestamp.tv_sec = seconds;
    return alert;
}

int main(void)
{
    correlation_engine_t engine;
    alert_t input[1];
    alert_t output[2];
    size_t count;

    assert(correlation_init(&engine, 300) == 0);

    input[0] = make_alert(ALERT_TYPE_PORT_SCAN, 1000);
    count = correlation_process_alerts(&engine, input, 1, output, 2);
    assert(count == 0);

    input[0] = make_alert(ALERT_TYPE_SSH_BRUTE_FORCE, 1010);
    count = correlation_process_alerts(&engine, input, 1, output, 2);
    assert(count == 0);

    input[0] = make_alert(ALERT_TYPE_BEACONING, 1020);
    count = correlation_process_alerts(&engine, input, 1, output, 2);
    assert(count == 1);
    assert(output[0].type == ALERT_TYPE_THREAT_CORRELATION);
    assert(output[0].severity == IDS_SEVERITY_CRITICAL);

    correlation_destroy(&engine);
    puts("test_correlation: ok");
    return 0;
}
