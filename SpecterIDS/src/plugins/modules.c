#include "modules.h"
#include "plugin_api.h"

#include <stdio.h>

void modules_print_builtin(void)
{
    size_t i;

    printf("Built-in module interfaces:\n");
    printf("  parser: datalink, arp, ipv4, ipv6, tcp, udp, icmp, icmpv6\n");
    printf("  detection:");
    for (i = 0; i < detection_builtin_module_count(); i++) {
        printf(" %s", detection_builtin_module_name(i));
    }
    printf("\n");
    printf("  dynamic plugin ABI: %u entrypoint=%s\n",
           SPECTERIDS_PLUGIN_ABI_VERSION,
           SPECTERIDS_PLUGIN_ENTRYPOINT);
    printf("  output: console,file,jsonl,sqlite,pcap,metrics\n");
    printf("  enrichment: not_enabled\n");
}
