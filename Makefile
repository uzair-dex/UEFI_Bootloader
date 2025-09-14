.POSIX:
.PHONY: all clean

TARGET= write_gpt
CC= gcc
CFLAGS= -std=c23 -Wall -Wextra -Wpedantic -O2

all: $(TARGET)	

clean: 
	rm -f $(TARGET)

