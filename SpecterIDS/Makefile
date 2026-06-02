CC ?= gcc
TARGET := specterids

SRC := src/main.c $(sort $(wildcard src/*/*.c))
OBJ := $(SRC:.c=.o)

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS := $(shell pkg-config --libs libpcap 2>/dev/null)
SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS := $(shell pkg-config --libs sqlite3 2>/dev/null)
DL_LIBS := -ldl

CPPFLAGS := -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE $(PCAP_CFLAGS)
WARNFLAGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 \
	-Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wdouble-promotion
HARDENING := -fstack-protector-strong -D_FORTIFY_SOURCE=2
CSTD := -std=c11
CFLAGS_DEBUG := $(CSTD) $(WARNFLAGS) $(HARDENING) -g -O0 -DDEBUG -fsanitize=address,undefined
CFLAGS_RELEASE := $(CSTD) $(WARNFLAGS) $(HARDENING) -O2 -DNDEBUG
CFLAGS ?= $(CFLAGS_RELEASE)
LDLIBS := $(if $(PCAP_LIBS),$(PCAP_LIBS),-lpcap) $(DL_LIBS) -pthread

TEST_CFLAGS := $(CSTD) $(WARNFLAGS) $(HARDENING) -g -O0 -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -fsanitize=address,undefined
TEST_BINS := tests/test_rules tests/test_detection tests/test_parser tests/test_queue tests/test_pool tests/test_event tests/test_correlation tests/test_config tests/test_pcap_regression tests/test_plugin_loading

COMMON_SRC := src/utils/common.c
CONFIG_SRC := src/config/config.c
CORRELATION_SRC := src/correlation/correlation.c
DATALINK_SRC := src/datalink/datalink.c
DETECTION_SRC := src/detection/detection.c
EVENT_SRC := src/events/event.c
PARSER_SRC := src/parser/parser.c
POOL_SRC := src/memory/pool.c
QUEUE_SRC := src/queues/queue.c
RULES_SRC := src/rules/rules.c
STATS_SRC := src/utils/stats.c

.PHONY: all clean run debug release sqlite plugins test integration-test regression-test analyze format benchmark fuzz fixtures

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OBJ) -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug: CFLAGS := $(CFLAGS_DEBUG)
debug: LDLIBS += -fsanitize=address,undefined
debug: clean $(TARGET)
	rm -f $(OBJ)

release: CFLAGS := $(CFLAGS_RELEASE)
release: clean $(TARGET)
	rm -f $(OBJ)

sqlite: CPPFLAGS += -DSPECTERIDS_ENABLE_SQLITE $(SQLITE_CFLAGS)
sqlite: LDLIBS += $(if $(SQLITE_LIBS),$(SQLITE_LIBS),-lsqlite3)
sqlite: clean $(TARGET)
	rm -f $(OBJ)

plugins/libspecter_portscan.so: plugins/specter_portscan_plugin.c include/plugin_api.h include/detection.h include/parser.h include/common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared plugins/specter_portscan_plugin.c -o $@

plugins: plugins/libspecter_portscan.so

run: $(TARGET)
	@if [ -z "$(IFACE)" ]; then \
		echo "Use: make run IFACE=eth0"; \
		exit 1; \
	fi
	sudo ./$(TARGET) -i $(IFACE)

tests/test_rules: tests/test_rules.c $(RULES_SRC) $(COMMON_SRC) include/rules.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_rules.c $(RULES_SRC) $(COMMON_SRC) -o $@

tests/test_detection: tests/test_detection.c $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) include/detection.h include/rules.h include/parser.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_detection.c $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) $(DL_LIBS) -pthread -o $@

tests/test_parser: tests/test_parser.c $(PARSER_SRC) $(DATALINK_SRC) $(COMMON_SRC) include/parser.h include/datalink.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_parser.c $(PARSER_SRC) $(DATALINK_SRC) $(COMMON_SRC) -o $@

tests/test_queue: tests/test_queue.c $(QUEUE_SRC) include/queue.h
	$(CC) $(TEST_CFLAGS) tests/test_queue.c $(QUEUE_SRC) -pthread -o $@

tests/test_pool: tests/test_pool.c $(POOL_SRC) $(QUEUE_SRC) include/pool.h include/queue.h
	$(CC) $(TEST_CFLAGS) tests/test_pool.c $(POOL_SRC) $(QUEUE_SRC) -pthread -o $@

tests/test_event: tests/test_event.c $(EVENT_SRC) include/event.h include/detection.h include/parser.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_event.c $(EVENT_SRC) $(COMMON_SRC) -pthread -o $@

tests/test_correlation: tests/test_correlation.c $(CORRELATION_SRC) $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) include/correlation.h include/detection.h
	$(CC) $(TEST_CFLAGS) tests/test_correlation.c $(CORRELATION_SRC) $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) $(DL_LIBS) -pthread -o $@

tests/test_config: tests/test_config.c $(CONFIG_SRC) $(COMMON_SRC) include/config.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_config.c $(CONFIG_SRC) $(COMMON_SRC) -o $@

tests/test_pcap_regression: tests/test_pcap_regression.c $(PARSER_SRC) $(DATALINK_SRC) $(COMMON_SRC) include/parser.h include/datalink.h
	$(CC) $(TEST_CFLAGS) $(PCAP_CFLAGS) tests/test_pcap_regression.c $(PARSER_SRC) $(DATALINK_SRC) $(COMMON_SRC) -o $@ $(if $(PCAP_LIBS),$(PCAP_LIBS),-lpcap)

tests/test_plugin_loading: tests/test_plugin_loading.c $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) plugins/libspecter_portscan.so include/detection.h include/plugin_api.h
	$(CC) $(TEST_CFLAGS) tests/test_plugin_loading.c $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) $(DL_LIBS) -pthread -o $@

tests/fuzz_parser: tests/fuzz_parser.c $(PARSER_SRC) $(DATALINK_SRC) $(COMMON_SRC) include/parser.h include/datalink.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/fuzz_parser.c $(PARSER_SRC) $(DATALINK_SRC) $(COMMON_SRC) -o $@

tests/benchmark: tests/benchmark.c $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) $(STATS_SRC) include/detection.h include/rules.h include/stats.h
	$(CC) $(TEST_CFLAGS) tests/benchmark.c $(DETECTION_SRC) $(RULES_SRC) $(COMMON_SRC) $(STATS_SRC) $(DL_LIBS) -pthread -o $@

test: fixtures $(TEST_BINS)
	./tests/test_rules
	./tests/test_detection
	./tests/test_parser
	./tests/test_queue
	./tests/test_pool
	./tests/test_event
	./tests/test_correlation
	./tests/test_config
	./tests/test_pcap_regression
	./tests/test_plugin_loading

integration-test: test fuzz benchmark

regression-test: $(TARGET) test
	./$(TARGET) --pcap samples/example.pcap --quiet
	./$(TARGET) --pcap tests/pcaps/ipv6.pcap --quiet
	./$(TARGET) --pcap tests/pcaps/malformed.pcap --quiet || true
	sh tests/test_determinism.sh ./$(TARGET) tests/pcaps/portscan.pcap
	sh tests/test_pcap_errors.sh ./$(TARGET)

fuzz: tests/fuzz_parser
	./tests/fuzz_parser

benchmark: tests/benchmark
	./tests/benchmark | tee benchmarks.md

fixtures:
	./scripts/generate-fixtures.sh

analyze:
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,style,performance,portability --std=c11 --suppress=missingIncludeSystem -Iinclude src tests; \
	else \
		$(CC) $(CPPFLAGS) $(CSTD) $(WARNFLAGS) -fanalyzer -fsyntax-only $(SRC); \
	fi

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		find include src tests plugins -name '*.[ch]' -exec clang-format -i {} +; \
	else \
		echo "clang-format not found"; \
	fi

clean:
	rm -f $(OBJ) src/*.o src/*/*.o $(TARGET) $(TEST_BINS) tests/fuzz_parser tests/benchmark tests/*.tmp plugins/libspecter_portscan.so
