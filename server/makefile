# References : ../examples/autotest-validate/Makefile
CROSS_COMPILE = 

INCLUDES = -I ../aesd-char-driver/

ifeq ($(CC),)
	CC ?= $(CROSS_COMPILE)gcc
endif

ifeq ($(CFLAGS),)
	CFLAGS ?= -g -Wall -Werror ${INCLUDES}
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