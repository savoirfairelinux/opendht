noinst_LTLIBRARIES = libargon2.la

libargon2_la_CFLAGS = -std=c89 -fPIC -pthread -O3 -Wall

libargon2_la_SOURCES = \
        argon2.c \
        core.c \
        blake2/blake2b.c \
        thread.c \
        encoding.c \
        ref.c

EXTRA_libargon2_la_SOURCES = opt.c
