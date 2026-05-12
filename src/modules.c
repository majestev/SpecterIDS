#include "modules.h"

#include <stdio.h>

void modules_print_builtin(void)
{
    printf("Built-in module interfaces:\n");
    printf("  parser: ethernet_ipv4\n");
    printf("  detection: behavioral_rules\n");
    printf("  output: console,file,jsonl,pcap,metrics\n");
    printf("  enrichment: reserved_for_future\n");
}
