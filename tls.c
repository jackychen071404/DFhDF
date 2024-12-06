#include "tls.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#define HASH_SIZE 128

struct hash_element
{
    pthread_t tid;
    TLS *tls;
    struct hash_element *next;
};
struct hash_element *hash_table[HASH_SIZE];

int page_size;
int inits = 0;

void tls_handle_page_fault(int sig, siginfo_t *si, void *context)
{
    unsigned int p_fault = ((unsigned long int)si->si_addr) & ~(page_size - 1);
    unsigned int i;
    unsigned int j;
    for (i = 0; i < HASH_SIZE; i++) {
        if (hash_table[i]->tls != NULL) {
            for (j = 0; j < hash_table[i]->tls->page_num; j++) {
                if (hash_table[i]->tls->pages[j]->address == p_fault) {
                    pthread_exit(NULL);
                    return;
                }
            }
        }
    }
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    raise(sig);
}

void tls_init()
{
    int i;
    for (i = 0; i < HASH_SIZE; i++) {
        hash_table[i] = calloc(1, sizeof(struct hash_element));
        hash_table[i]->tls = NULL;
    }

    struct sigaction sigact;
    /* get the size of a page */
    page_size = getpagesize();
    /* install the signal handler for page faults (SIGSEGV, SIGBUS) */
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_SIGINFO; /* use extended signal handling */
    sigact.sa_sigaction = tls_handle_page_fault;
    sigaction(SIGBUS, &sigact, NULL);
    sigaction(SIGSEGV, &sigact, NULL);
    inits = 1;
}

int tls_create(unsigned int size)
{
    pthread_t id = pthread_self();
    if (!inits) tls_init();

    if (size <= 0) return -1;

    unsigned int i;
    for (i = 0; i < HASH_SIZE; i++) {
        if (hash_table[i] != NULL && hash_table[i]->tid == id)  {
            return -1;
        }
    }

    TLS *new_tls = calloc(1, sizeof(TLS));
    new_tls->tid = id; //tls fields
    new_tls->size = size;
    new_tls->page_num = (size + page_size - 1) / page_size;
    new_tls->pages = calloc(new_tls->page_num, sizeof(struct page *));
    for (i = 0; i < new_tls->page_num; i++) { //page addresses
        struct page *p = calloc(1, sizeof(struct page));
        p->address = (unsigned long int)mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
        p->ref_count = 1;
        new_tls->pages[i] = p;
    }
    for (i = 0; i < HASH_SIZE; i++) { //into the hash table
        if (hash_table[i]->tls == NULL) {
            hash_table[i]->tid = id;
            hash_table[i]->tls = new_tls;
            break;
        }
    }
    return 0;
}

void tls_protect(struct page *p)
{
    if (mprotect((void *)p->address, page_size, 0))
    {
        fprintf(stderr, "tls_protect: could not protect page\n");
        exit(1);
    }
}

void tls_unprotect(struct page *p)
{
    if (mprotect((void *)p->address, page_size, PROT_READ | PROT_WRITE))
    {
        fprintf(stderr, "tls_unprotect: could not unprotect page\n");
        exit(1);
    }
}

int tls_read(unsigned int offset, unsigned int length, char *buffer)
{
    pthread_t id = pthread_self();
    int index = -1;
    int found = 0;
    unsigned int i;
    for (i = 0; i < HASH_SIZE; i++)
    {
        if (hash_table[i] != NULL && hash_table[i]->tid == id)
        {
            index = i;
            found = 1;
            break;
        }
    }

    if (!found || hash_table[index]->tls == NULL) return -1;

    if ((offset + length) > hash_table[index]->tls->size) return -1;

    unsigned int cnt, idx;
    for (cnt = 0, idx = offset; idx < (offset + length); ++cnt, ++idx) //read function
    {
        struct page *p;
        unsigned int pn, poff;
        pn = idx / page_size;
        poff = idx % page_size;
        p = hash_table[index]->tls->pages[pn];
        // src = ((char *)p->address) + poff;
        tls_unprotect(p);
        buffer[cnt] = *((char *)p->address + poff);
        tls_protect(p);
    }
    return 0;
}

int tls_write(unsigned int offset, unsigned int length, char *buffer)
{
    pthread_t id = pthread_self();
    int index = -1;
    int found = 0;
    unsigned int i;
    for (i = 0; i < HASH_SIZE; i++) {
        if (hash_table[i] != NULL && hash_table[i]->tid == id) {
            index = i;
            found = 1;
            break;
        }
    }

    if (!found || hash_table[index]->tls == NULL) return -1;

    if ((offset + length) > hash_table[index]->tls->size) return -1;

    // write operation
    unsigned int cnt, idx;
    for (cnt = 0, idx = offset; idx < (offset + length); ++cnt, ++idx)
    {
        struct page *p, *copy;
        unsigned int pn, poff;
        pn = idx / page_size;
        poff = idx % page_size;

        p = hash_table[index]->tls->pages[pn];
        tls_unprotect(p);
        if (p->ref_count > 1)
        {
            copy = (struct page *)calloc(1, sizeof(struct page));
            copy->address = (unsigned long int)mmap(0, page_size, PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
            tls_unprotect(copy);
            memcpy((void *)copy->address, (void *)p->address, page_size);
            copy->ref_count = 1;
            hash_table[index]->tls->pages[pn] = copy;
            p->ref_count--;
            tls_protect(p);
            p = copy;
        }
        char *dst = ((char *)p->address) + poff;
        *dst = buffer[cnt];
    }

    return 0;
}

int tls_destroy()
{
    pthread_t id = pthread_self();
    int index = -1;
    int found = 0;
    unsigned int i;
    for (i = 0; i < HASH_SIZE; i++)
    {
        if (hash_table[i] != NULL && hash_table[i]->tid == id)
        {
            index = i;
            found = 1;
            break;
        }
    }

    if (!found || hash_table[index]->tls == NULL) return -1;
    for (i = 0; i < hash_table[index]->tls->page_num; i++) {
        if (hash_table[index]->tls->pages[i]->ref_count == 1)  {
            hash_table[index]->tls->pages[i]->ref_count--;
            // munmap((void *)hash_table[index]->tls->pages[i]->address, page_size);
            free(hash_table[index]->tls->pages[i]);
        }  else  {
            hash_table[index]->tls->pages[i]->ref_count--;
        }
    }
    free(hash_table[index]->tls->pages);
    free(hash_table[index]->tls);
    hash_table[index]->tls = NULL;

    return 0;
}

int tls_clone(pthread_t tid) {
    pthread_t id = pthread_self();
    int index = -1;
    int found = 0;
    unsigned int i;
    for (i = 0; i < HASH_SIZE; i++) {
        if (hash_table[i] != NULL && hash_table[i]->tid == id) return -1;
    }
    for (i = 0; i < HASH_SIZE; i++)
    {
        if (hash_table[i] != NULL && hash_table[i]->tid == tid)
        {
            index = i;
            found = 1;
            break;
        }
    }
    if (!found || hash_table[index]->tls == NULL) return -1;
    TLS *new_tls = calloc(1, sizeof(TLS));
    new_tls->tid = id;
    new_tls->size = hash_table[index]->tls->size;
    new_tls->page_num = hash_table[index]->tls->page_num;
    new_tls->pages = calloc(new_tls->page_num, sizeof(struct page *));
    for(i = 0; i < new_tls->page_num; i++) {
        new_tls->pages[i] = hash_table[index]->tls->pages[i];
        new_tls->pages[i]->ref_count++;
    }
    for (i = 0; i < HASH_SIZE; i++) {
        if (hash_table[i]->tls == NULL) {
            hash_table[i]->tid = id;
            hash_table[i]->tls = new_tls;
            break;
        }
    }
    return 0;
}
