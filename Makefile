CC ?= gcc
TARGET := specterids

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS := $(shell pkg-config --libs libpcap 2>/dev/null)

CPPFLAGS := -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE $(PCAP_CFLAGS)
WARNFLAGS := -Wall -Wextra -Wpedantic
HARDENING := -fstack-protector-strong -D_FORTIFY_SOURCE=2
CSTD := -std=c11
CFLAGS ?= $(CSTD) $(WARNFLAGS) $(HARDENING) -O2
LDLIBS := $(if $(PCAP_LIBS),$(PCAP_LIBS),-lpcap) -pthread

TEST_CFLAGS := $(CSTD) $(WARNFLAGS) -g -O0 -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
TEST_BINS := tests/test_rules tests/test_detection tests/test_parser tests/test_queue tests/test_event tests/test_correlation

.PHONY: all clean run debug release test integration-test analyze format benchmark fuzz

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OBJ) -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug: CFLAGS := $(CSTD) $(WARNFLAGS) -g -O0 -DDEBUG -fsanitize=address,undefined -fstack-protector-strong
debug: LDLIBS += -fsanitize=address,undefined
debug: clean $(TARGET)

release: CFLAGS := $(CSTD) $(WARNFLAGS) $(HARDENING) -O2 -DNDEBUG
release: clean $(TARGET)

run: $(TARGET)
	@if [ -z "$(IFACE)" ]; then \
		echo "Use: make run IFACE=eth0"; \
		exit 1; \
	fi
	sudo ./$(TARGET) -i $(IFACE)

tests/test_rules: tests/test_rules.c src/rules.c src/common.c include/rules.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_rules.c src/rules.c src/common.c -o $@

tests/test_detection: tests/test_detection.c src/detection.c src/rules.c src/common.c include/detection.h include/rules.h include/parser.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_detection.c src/detection.c src/rules.c src/common.c -pthread -o $@

tests/test_parser: tests/test_parser.c src/parser.c src/common.c include/parser.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_parser.c src/parser.c src/common.c -o $@

tests/test_queue: tests/test_queue.c src/queue.c include/queue.h
	$(CC) $(TEST_CFLAGS) tests/test_queue.c src/queue.c -pthread -o $@

tests/test_event: tests/test_event.c src/event.c include/event.h include/detection.h include/parser.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/test_event.c src/event.c src/common.c -pthread -o $@

tests/test_correlation: tests/test_correlation.c src/correlation.c src/detection.c src/rules.c src/common.c include/correlation.h include/detection.h
	$(CC) $(TEST_CFLAGS) tests/test_correlation.c src/correlation.c src/detection.c src/rules.c src/common.c -pthread -o $@

tests/fuzz_parser: tests/fuzz_parser.c src/parser.c src/common.c include/parser.h include/common.h
	$(CC) $(TEST_CFLAGS) tests/fuzz_parser.c src/parser.c src/common.c -o $@

tests/benchmark: tests/benchmark.c src/detection.c src/rules.c src/common.c src/stats.c include/detection.h include/rules.h include/stats.h
	$(CC) $(TEST_CFLAGS) tests/benchmark.c src/detection.c src/rules.c src/common.c src/stats.c -pthread -o $@

test: $(TEST_BINS)
	./tests/test_rules
	./tests/test_detection
	./tests/test_parser
	./tests/test_queue
	./tests/test_event
	./tests/test_correlation

integration-test: test fuzz benchmark

fuzz: tests/fuzz_parser
	./tests/fuzz_parser

benchmark: tests/benchmark
	./tests/benchmark | tee docs/benchmarks.md

analyze:
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,style,performance,portability --std=c11 --suppress=missingIncludeSystem -Iinclude src tests; \
	else \
		$(CC) $(CPPFLAGS) $(CSTD) $(WARNFLAGS) -fanalyzer -fsyntax-only $(SRC); \
	fi

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i include/*.h src/*.c tests/*.c; \
	else \
		echo "clang-format not found"; \
	fi

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_BINS) tests/fuzz_parser tests/benchmark tests/*.tmp
