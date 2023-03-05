# References : ../examples/autotest-validate/Makefile
CROSS_COMPILE = 

ifeq ($(CC),)
	CC ?= $(CROSS_COMPILE)gcc
endif

ifeq ($(CFLAGS),)
	CFLAGS ?= -g -Wall -Werror
endif

ifeq ($(LDFLAGS),)
	LDFLAGS ?= -pthread -lrt
endif

SRC ?= aesdsocket.c
TARGET ?= aesdsocket

all: $(TARGET)

$(TARGET) : ${SRC}
	$(CC) $(CFLAGS) ${SRC} -o ${TARGET} $(LDFLAGS)

clean:
	rm -f *.o ${TARGET}