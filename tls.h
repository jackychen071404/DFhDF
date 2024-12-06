#ifndef TLS_H
#define TLS_H

#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>


typedef struct thread_local_storage
{
    pthread_t tid;
    unsigned int size;     /* size in bytes */
    unsigned int page_num; /* number of pages */
    struct page **pages;   /* array of pointers to pages */
} TLS;
struct page
{
    unsigned long int address; /* start address of page */
    int ref_count;             /* counter for shared pages */
};

int tls_create(unsigned int size);

int tls_write(unsigned int offset, unsigned int length, char *buffer);
int tls_read(unsigned int offset, unsigned int length, char *buffer);
int tls_destroy();
int tls_clone(pthread_t tid);

#endif
