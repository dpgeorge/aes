CC = gcc
CFLAGS = -std=c99 -m32 -Os

all: aes.o
	size aes.o
