/*
 * CS 2110 Spring 2019
 * Author: Brayden Richardson
 */

/* we need this for uintptr_t */
#include <stdint.h>
/* we need this for memcpy/memset */
#include <string.h>
/* we need this to print out stuff*/
#include <stdio.h>
/* we need this for the metadata_t struct and my_malloc_err enum definitions */
#include "my_malloc.h"
/* include this for any boolean methods */
#include <stdbool.h>

/*Function Headers
 * Here is a place to put all of your function headers
 * Remember to declare them as static
 */
static metadata_t* find_right(metadata_t*);
static metadata_t* find_left(metadata_t*);
static metadata_t* merge(metadata_t* left, metadata_t* right);
static metadata_t* double_merge(metadata_t* left, metadata_t* middle, metadata_t* right);
static metadata_t* split_block(metadata_t* block, size_t size);
static void add_to_size_list(metadata_t* add_block);
static void remove_from_size_list(metadata_t* remove_block);
static void set_canary(metadata_t* block);
/* Our freelist structure - our freelist is represented as a singly linked list
 * the size_list orders the free blocks by size in ascending order
 */

metadata_t *size_list;

/* Set on every invocation of my_malloc()/my_free()/my_realloc()/
 * my_calloc() to indicate success or the type of failure. See
 * the definition of the my_malloc_err enum in my_malloc.h for details.
 * Similar to errno(3).
 */
enum my_malloc_err my_malloc_errno;

/* MALLOC
 * See PDF for documentation
 */
void *my_malloc(size_t size) {
    if (size > (SBRK_SIZE - TOTAL_METADATA_SIZE)) {
        my_malloc_errno = SINGLE_REQUEST_TOO_LARGE;
        return NULL;
    } else if (size == 0) {
        my_malloc_errno = NO_ERROR;
        return NULL;
    }
    metadata_t* curr = size_list;
    while (curr) {
        if (curr -> size > (size + MIN_BLOCK_SIZE)) {
            metadata_t* retBlock = split_block(curr, size);
            set_canary(retBlock);
            retBlock += 1;
            my_malloc_errno = NO_ERROR;
            return (void*)retBlock;
        } else if (curr -> size == size) {
            remove_from_size_list(curr);
            set_canary(curr);
            metadata_t* ptr = curr;
            ptr += 1;
            my_malloc_errno = NO_ERROR;
            return (void*)ptr;
        }
        curr = curr -> next;
    }
    metadata_t* block = (metadata_t*)my_sbrk(SBRK_SIZE);
    if (!block) {
        my_malloc_errno = OUT_OF_MEMORY;
        return NULL;
    }
    block -> size = SBRK_SIZE - TOTAL_METADATA_SIZE;
    metadata_t* left = find_left(block);
    metadata_t* right = find_right(block);
    metadata_t* newBlock;
    if (left && right) {
        newBlock = double_merge(left, block, right);
    } else if (left) {
        newBlock = merge(left, block);
    } else if (right) {
        newBlock = merge(block, right);
    } else {
        newBlock = block;
    }
    if (newBlock -> size >= (size + MIN_BLOCK_SIZE)) {
        metadata_t* retBlock = split_block(newBlock, size);
        set_canary(retBlock);
        retBlock += 1;
        my_malloc_errno = NO_ERROR;
        return (void*)retBlock;
    } else if (newBlock -> size == size) {
        remove_from_size_list(newBlock);
        set_canary(newBlock);
        newBlock += 1;
        my_malloc_errno = NO_ERROR;
        return (void*)newBlock;
    }
    my_malloc_errno = NO_ERROR;
    return NULL;
}

/* REALLOC
 * See PDF for documentation
 */
void *my_realloc(void *ptr, size_t size) {
    if (!ptr) {
        return my_malloc(size);
    }
    metadata_t* newPtr = ptr;
    newPtr -= 1;
    unsigned long canary = ((uintptr_t)newPtr ^ CANARY_MAGIC_NUMBER) + 1890;
    if (newPtr -> canary != canary) {
        my_malloc_errno = CANARY_CORRUPTED;
        return NULL;
    }
    unsigned long* tailCanaryPtr = (unsigned long*)((uint8_t*)newPtr + sizeof(*newPtr) + newPtr -> size);
    if (*tailCanaryPtr != canary) {
        my_malloc_errno = CANARY_CORRUPTED;
        return NULL;
    }
    if (ptr && size == 0) {
        my_free(ptr);
        return NULL;
    }
    metadata_t* oldPtr = (metadata_t*)ptr;
    oldPtr += 1;
    unsigned long oldSize = oldPtr -> size;
    unsigned long newSize = (unsigned long)size;
    void* newBlock = my_malloc(size);
    if (oldSize >= newSize) {
        newBlock = memcpy(newBlock, ptr, (size_t)newSize);
    } else if (newSize > oldSize) {
        newBlock = memcpy(newBlock, ptr, (size_t)oldSize);
    }
    my_malloc_errno = NO_ERROR;
    return newBlock;
}

/* CALLOC
 * See PDF for documentation
 */
void *my_calloc(size_t nmemb, size_t size) {
    void* block = my_malloc(nmemb * size);
    if (!block) {
        return NULL;
    }
    return memset(block, 0, nmemb * size);
}

/* FREE
 * See PDF for documentation
 */
void my_free(void *ptr) {
    if (!ptr) {
        my_malloc_errno = NO_ERROR;
        return;
    }
    metadata_t* newPtr = ptr;
    newPtr -= 1;
    unsigned long canary = ((uintptr_t)newPtr ^ CANARY_MAGIC_NUMBER) + 1890;
    if (newPtr -> canary != canary) {
        my_malloc_errno = CANARY_CORRUPTED;
        return;
    }
    unsigned long* tailCanaryPtr = (unsigned long*)((uint8_t*)newPtr + sizeof(*newPtr) + newPtr -> size);
    if (*tailCanaryPtr != canary) {
        my_malloc_errno = CANARY_CORRUPTED;
        return;
    }
    metadata_t* left = find_left(newPtr);
    metadata_t* right = find_right(newPtr);
    metadata_t* newBlock;
    if (left && right) {
        newBlock = double_merge(left, newPtr, right);
    } else if (left) {
        newBlock = merge(left, newPtr);
    } else if (right) {
        newBlock = merge(newPtr, right);
    } else {
        newBlock = newPtr;
    }
    add_to_size_list(newBlock);
    my_malloc_errno = NO_ERROR;
}

static metadata_t* find_right(metadata_t* block) {
    if(!size_list) {
        return NULL;
    }
    metadata_t* curr = size_list;
    metadata_t* next = curr -> next;
    metadata_t* ptr = curr;
    unsigned long temp = block -> size + TOTAL_METADATA_SIZE;
    ptr = (metadata_t*)((uint8_t*)ptr - temp);
    if (ptr == block) {
        return curr;
    }
    while (next) {
        curr = next;
        next = curr -> next;
        ptr = curr;
        temp = block -> size + TOTAL_METADATA_SIZE;
        ptr = (metadata_t*)((uint8_t*)ptr - temp);
        if (ptr == block) {
            return curr;
        }
    }
    return NULL;
}

static metadata_t* find_left(metadata_t* block) {
    metadata_t* curr = size_list;
    metadata_t* prev;
    metadata_t* ptr;
    while (curr) {
        prev = curr;
        curr = curr -> next;
        ptr = prev;
        unsigned long temp = prev -> size + TOTAL_METADATA_SIZE;
        ptr = (metadata_t*)((uint8_t*)ptr + temp);
        if (ptr == block) {
            return prev;
        }
    }
    return NULL;
}

static metadata_t* merge(metadata_t* left, metadata_t* right) {
    remove_from_size_list(left);
    remove_from_size_list(right);
    left -> size += (right -> size + TOTAL_METADATA_SIZE);
    return left;
}

static metadata_t* double_merge(metadata_t* left, metadata_t* middle, metadata_t* right) {
    remove_from_size_list(left);
    remove_from_size_list(middle);
    remove_from_size_list(right);
    left -> size += (middle -> size) + (right -> size) + (2*TOTAL_METADATA_SIZE);
    return left;
}

static metadata_t* split_block(metadata_t* block, size_t size) {
    remove_from_size_list(block);
    uint8_t* ptr = (uint8_t*) block;
    ptr += (block -> size + TOTAL_METADATA_SIZE);
    ptr -= (size + TOTAL_METADATA_SIZE);
    metadata_t* newPtr = (metadata_t*) ptr;
    newPtr -> size = size;
    block -> size -= (size + TOTAL_METADATA_SIZE);
    add_to_size_list(block);
    return newPtr;
}

static void add_to_size_list(metadata_t* add_block) {
    if (!size_list) {
        size_list = add_block;
        return;
    }
    metadata_t* left = find_left(add_block);
    metadata_t* right = find_right(add_block);
    metadata_t* newBlock;
    if (left && right) {
        newBlock = double_merge(left, add_block, right);
    } else if (left) {
        newBlock = merge(left, add_block);
    } else if (right) {
        newBlock = merge(add_block, right);
    } else {
        newBlock = add_block;
    }
    if (newBlock -> size <= size_list -> size) {
        newBlock -> next = size_list;
        size_list = newBlock;
        return;
    }
    metadata_t* curr = size_list;
    metadata_t* prev;
    while (curr) {
        prev = curr;
        curr = curr -> next;
        if (curr && newBlock -> size <= curr -> size) {
            prev -> next = newBlock;
            newBlock -> next = curr;
            return;
        }
    }
    prev -> next = newBlock;
    newBlock -> next = NULL;
}

static void remove_from_size_list(metadata_t* remove_block) {
    metadata_t* curr = size_list;
    metadata_t* prev;
    if (curr == remove_block) {
        size_list = curr -> next;
        curr -> next = NULL;
    }
    while (curr) {
        prev = curr;
        curr = curr -> next;
        if (curr == remove_block) {
            prev -> next = curr -> next;
            curr -> next = NULL;
            return;
        }
    }
}

static void set_canary(metadata_t* block) {
    unsigned long canary = ((uintptr_t)block ^ CANARY_MAGIC_NUMBER) + 1890;
    block -> canary = canary;
    unsigned long* tailCanaryPtr = (unsigned long*)((uint8_t*)block + sizeof(*block) + block -> size);
    *tailCanaryPtr = canary;
}
