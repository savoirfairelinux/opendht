noinst_LTLIBRARIES = libargon2.la

libargon2_la_CFLAGS = -std=c89 -fPIC -pthread -O3 -Wall

libargon2_la_SOURCES = \
        argon2.c \
        core.c \
        blake2/blake2b.c \
        thread.c \
        encoding.c \
        ref.c

noinst_HEADERS = \
        argon2.h \
        core.h \
        blake2/blake2.h \
        blake2/blake2-impl.h \
        blake2/blamka-round-ref.h \
        blake2/blamka-round-opt.h \
        thread.h \
        encoding.h \
        opt.h \
        ref.h
