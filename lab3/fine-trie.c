/* A simple, (reverse) trie.  Only for use with 1 thread. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <time.h>
#include "trie.h"

extern volatile int finished;
FILE *g_logfp = NULL;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

struct trie_node {
    pthread_mutex_t lock;
    pthread_t thread;
    int islocked;
    struct trie_node *next;  /* parent list */
    unsigned int strlen; /* Length of the key */
    int32_t ip4_address; /* 4 octets */
    struct trie_node *children; /* Sorted list of children */
    char key[64]; /* Up to 64 chars */
};

static struct trie_node * root = NULL;
pthread_mutex_t rootlock = PTHREAD_MUTEX_INITIALIZER;

void _nodelock(struct trie_node *node, int line, const char *func)
{
    struct timespec tm;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
    LOG_PRINT2("*** 1:tm (%ul.%ul) _nodelock thread[%u], islocked=%d, node[%p], %s, %d\n", 
        tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), node->islocked, node, func, line);
    assert(node);
    if(node->islocked) {
     //   assert(node->thread != pthread_self());
    }
    
    //if (node->islocked && pthread_self() == node->thread){
        //LOG_PRINT("*** 1 _nodelock thread[%u], islocked=%d, node[%p]\n", (unsigned int)pthread_self(), node->islocked, node);
        //return;
    //}
    //LOG_PRINT("*** 2:tm (%ul.%ul) _nodelock thread[%u], islocked=%d, node[%p]\n", tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), node->islocked, node);
    //LOG_PRINT("*** 0 _nodelock thread[%u], islocked=%d, node[%p]\n", (unsigned int)pthread_self(), node->islocked, node);
    pthread_mutex_lock(&(node->lock));
    //LOG_PRINT("*** 3:tm (%ul.%ul) _nodelock thread[%u], islocked=%d, node[%p]\n", tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), node->islocked, node);
    //node->thread = pthread_self();
    //node->islocked = 1;
}

void _nodeunlock(struct trie_node *node, int line, const char *func)
{
    struct timespec tm;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
    LOG_PRINT2("*** 1:tm (%ul.%ul) _nodeunlock thread[%u], islocked=%d, node[%p], %s, %d\n", 
        tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), node->islocked, node, func, line);
    //pthread_mutex_lock(&g_lock);
    if (node == NULL)
    {
        //LOG_PRINT("*** _nodeunlock thread[%u]\n", (unsigned int)pthread_self());
        fflush(stdout);
        sleep(2);
    }
    assert(node);
    //if ((!node->islocked) && pthread_self() == node->thread) {
        //LOG_PRINT("*** 0 _nodeunlock thread[%u], islocked=%d, node[%p]\n", (unsigned int)pthread_self(), node->islocked, node);
        //pthread_mutex_unlock(&g_lock);
        //return;
    //}
    //assert (node->islocked);
    //assert (pthread_self() == node->thread);

    //LOG_PRINT("*** 1 _nodeunlock thread[%u], islocked=%d, node[%p]\n", (unsigned int)pthread_self(), node->islocked, node);
    //assert(node->islocked != 0);
    //node->islocked = 0;
    //node->thread = 0;
    //pthread_mutex_unlock(&g_lock);
    pthread_mutex_unlock(&node->lock);
    
}

struct trie_node * new_leaf (const char *string, size_t strlen, int32_t ip4_address) {
    struct trie_node *new_node = malloc(sizeof(struct trie_node));
    if (!new_node) {
        printf ("WARNING: Node memory allocation failed.  Results may be bogus.\n");
        return NULL;
    }

    assert(strlen < 64);
    assert(strlen > 0);

    new_node->next = NULL;
    new_node->strlen = strlen;
    strncpy(new_node->key, string, strlen);
    new_node->key[strlen] = '\0';
    new_node->ip4_address = ip4_address;
    new_node->children = NULL;
    new_node->islocked = 0;
    new_node->thread = 0;
    pthread_mutex_init(&new_node->lock, NULL);

    return new_node;
}

void delete_leaf(struct trie_node *node)
{
    assert(node);
    //LOG_PRINT("*** 1 _nodeunlock thread[%u], islocked=%d, node[%p]\n", (unsigned int)pthread_self(), node->islocked, node);
    pthread_mutex_destroy(&node->lock);
    free(node);
    return;
}

int compare_keys (const char *string1, int len1, const char *string2, int len2, int *pKeylen) {
    int keylen, offset1, offset2;
    keylen = len1 < len2 ? len1 : len2;
    offset1 = len1 - keylen;
    offset2 = len2 - keylen;

    assert (keylen > 0);

    if (pKeylen)
      *pKeylen = keylen;
    return strncmp(&string1[offset1], &string2[offset2], keylen);
}

void init(int numthreads) {
    if (numthreads != 1)
      printf("WARNING: This Trie is only safe to use with one thread!!!  You have %d!!!\n", numthreads);

    root = NULL;
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the 
 * parent, or what should be the parent if not found.
 * 
 */
struct trie_node * 
_search (struct trie_node *node, const char *string, size_t strlen) {

    int keylen, cmp;

    // First things first, check if we are NULL 
    if (node == NULL) return NULL;

    assert(node->strlen < 64);

    // See if this key is a substring of the string passed in
    cmp = compare_keys(node->key, node->strlen, string, strlen, &keylen);
    if (cmp == 0) {
        // Yes, either quit, or recur on the children

        // If this key is longer than our search string, the key isn't here
        if (node->strlen > keylen) {
            return NULL;
        } else if (strlen > keylen) {
            // Recur on children list
            return _search(node->children, string, strlen - keylen);
        } else {
            assert (strlen == keylen);
            return node;
        }

    } else if (cmp < 0) {
        // No, look right (the node's key is "less" than the search key)
        return _search(node->next, string, strlen);
    } else {
        // Quit early
        return 0;
    }

}


int search  (const char *string, size_t strlen, int32_t *ip4_address) {
    struct trie_node *found;

    // Skip strings of length 0
    if (strlen == 0)
      return 0;

    found = _search(root, string, strlen);

    if (found && ip4_address)
      *ip4_address = found->ip4_address;

    return (found != NULL);
}

/* Recursive helper function */
int _insert (const char *string, size_t strlen, int32_t ip4_address, 
            struct trie_node *node, struct trie_node *parent, struct trie_node *left) {

    int cmp, keylen;
    struct timespec tm;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
    LOG_PRINT2("*** 1:tm (%ul.%ul) _insert thread[%u], node=%p, parent=%p, left=%p, string=%.*s, strlen[%d], ip4_address=%d\n", 
        tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), node, parent, left, strlen, string, strlen, ip4_address);
    // First things first, check if we are NULL 
    assert (node != NULL);
    assert (node->strlen < 64);

    _nodelock(node, __LINE__, __func__);
    // Take the minimum of the two lengths
    cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
    if (cmp == 0) {
        // Yes, either quit, or recur on the children

        // If this key is longer than our search string, we need to insert
        // "above" this node
        if (node->strlen > keylen) {
            struct trie_node *new_node;

            assert(keylen == strlen);
            assert((!parent) || parent->children == node);

            new_node = new_leaf (string, strlen, ip4_address);
            node->strlen -= keylen;
            new_node->children = node;

            assert ((!parent) || (!left));

            if (parent) {
                parent->children = new_node;
                LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                _nodeunlock(parent, __LINE__, __func__);
            } else if (left) {
                left->next = new_node;
                LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                _nodeunlock(left, __LINE__, __func__);
            } else if ((!parent) || (!left)) {
                root = new_node;
                pthread_mutex_unlock(&rootlock);
            }

            if (node){
                LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
            }
            else {
                LOG_PRINT("*** thread[%u], unlock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
            }
            _nodeunlock(node, __LINE__, __func__);
            return 1;

        } 
        else if (strlen > keylen) {
            if (node->children == NULL) {
                // Insert leaf here
                struct trie_node *new_node = new_leaf (string, strlen - keylen, ip4_address);
                node->children = new_node;

                //LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                if (node){
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                }
                else {
                    LOG_PRINT("*** thread[%u], unlock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
                }               
                if (parent) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                    _nodeunlock(parent, __LINE__, __func__);
                }
                else if (left) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                    _nodeunlock(left, __LINE__, __func__);
                }
                else
                {
                    pthread_mutex_unlock(&rootlock);
                }
                _nodeunlock(node, __LINE__, __func__);
                return 1;
            } 
            else {
                // Recur on children list, store "parent" (loosely defined)
                if (parent){
                  LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                  _nodeunlock(parent, __LINE__, __func__);
                }
                else if (left) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                    _nodeunlock(left, __LINE__, __func__);
                }
                else {
                    pthread_mutex_unlock(&rootlock);
                }
                return _insert(string, strlen - keylen, ip4_address, node->children, node, NULL);
            }
        } 
        else {
            assert (strlen == keylen);
            if (node->ip4_address == 0) {
                node->ip4_address = ip4_address;

                if (parent) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                    _nodeunlock(parent, __LINE__, __func__);
                }
                else if (left) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                    _nodeunlock(left, __LINE__, __func__);
                }
                else {
                    pthread_mutex_unlock(&rootlock);
                }
                //LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                if (node){
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                }
                else {
                    LOG_PRINT("*** thread[%u], unlock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
                }
                _nodeunlock(node, __LINE__, __func__);
                return 1;
            } 
            else 
            {
                //IF IT FAILS ON READDING IT
                if (parent) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                    _nodeunlock(parent, __LINE__, __func__);
                }
                else if (left) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                    _nodeunlock(left, __LINE__, __func__);
                }
                else {
                    pthread_mutex_unlock(&rootlock);
                }
                //LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                if (node){
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                }
                else {
                    LOG_PRINT("*** thread[%u], unlock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
                }
                _nodeunlock(node, __LINE__, __func__);
                //printf("I AM HERE WITH SOURABH"); fflush(stdout);
                return 0;
            }
        }

    } 
    else {

        /* Is there any common substring? */
        int i, cmp2, keylen2, overlap = 0;
        for (i = 1; i < keylen; i++) {
            cmp2 = compare_keys (&node->key[i], node->strlen - i, 
                        &string[i], strlen - i, &keylen2);
            assert (keylen2 > 0);
            if (cmp2 == 0) {
                overlap = 1;
                break;
            }
        }

        if (overlap) {
            // Insert a common parent, recur
            struct trie_node *new_node = new_leaf (&string[i], strlen - i, 0);
            int diff = node->strlen - i;
            assert ((node->strlen - diff) > 0);
            node->strlen -= diff;
            new_node->children = node;
            assert ((!parent) || (!left));
            if (new_node) {
                LOG_PRINT("*** thread[%u], lock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, new_node->strlen, new_node->key, new_node);
            }
            else {
                LOG_PRINT("*** thread[%u], lock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
            }
            _nodelock(new_node, __LINE__, __func__);
            if (node == root) {
                new_node->next = node->next;
                node->next = NULL;
                root = new_node;
                pthread_mutex_unlock(&rootlock);
            } else if (parent) {
                assert(parent->children == node);
                new_node->next = NULL;
                parent->children = new_node;
                LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                _nodeunlock(parent, __LINE__, __func__);
            } else if (left) {
                new_node->next = node->next;
                node->next = NULL;
                left->next = new_node;
                LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                _nodeunlock(left, __LINE__, __func__);
            } else if ((!parent) && (!left)) {
                assert(0);
                root = new_node;
            }
            _nodeunlock(node, __LINE__, __func__);
            return _insert(string, i, ip4_address, node, new_node, NULL);
        } 
        else if (cmp < 0) {
            if (node->next == NULL) {
                // Insert here
                struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
                node->next = new_node;
                if (parent) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                    _nodeunlock(parent, __LINE__, __func__);
                }
                else if (left) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                    _nodeunlock(left, __LINE__, __func__);
                }
                else {
                    pthread_mutex_unlock(&rootlock);
                }
                //LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                if (node){
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                }
                else {
                    LOG_PRINT("*** thread[%u], unlock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
                }
                _nodeunlock(node, __LINE__, __func__);
                return 1;
            } else {
                // No, recur right (the node's key is "greater" than  the search key)
                if (parent) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
                    _nodeunlock(parent, __LINE__, __func__);
                }
                else if (left) {
                    LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
                    _nodeunlock(left, __LINE__, __func__);
                }
                else {
                    pthread_mutex_unlock(&rootlock);
                }
                
                return _insert(string, strlen, ip4_address, node->next, NULL, node);
            }
        }
        else {
            // Insert here
            struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
            new_node->next = node;
            if (node == root) {
              root = new_node;
            }
            else if (parent && parent->children == node) {
              parent->children = new_node;
            }
        }

        if (parent) {
            LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, parent->strlen, parent->key, parent);
            _nodeunlock(parent, __LINE__, __func__);
        }
        else if (left) {
            LOG_PRINT("*** thread[%u], unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, left->strlen, left->key, left);
            _nodeunlock(left, __LINE__, __func__);
        }
        else {
            pthread_mutex_unlock(&rootlock);
        }
        //LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
        if (node){
            LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
        }
        else {
            LOG_PRINT("*** thread[%u], unlock: %d ***\n", (unsigned int)pthread_self(), __LINE__);
        }
        _nodeunlock(node, __LINE__, __func__);
        return 1;
    }
}

int insert (const char *string, size_t strlen, int32_t ip4_address) {
    // Skip strings of length 0
    struct timespec tm;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
    LOG_PRINT2("*** 1:tm (%ul.%ul) insert thread[%u], string=%s, strlen[%d], ip4_address=%d\n", 
        tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), string, strlen, ip4_address);
    if (strlen == 0)
      return 0;

    /* Edge case: root is null */
    if (root == NULL) {
        root = new_leaf (string, strlen, ip4_address);
        return 1;
    }
    pthread_mutex_lock(&rootlock);
    return _insert (string, strlen, ip4_address, root, NULL, NULL);
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the 
 * parent, or what should be the parent if not found.
 * 
 */
struct trie_node * 
_delete (struct trie_node *node, struct trie_node *pred, struct trie_node *lockbegnd, const char *string, size_t strlen) {
    int keylen, cmp;
    struct timespec tm;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
    LOG_PRINT2("*** 1:tm (%ul.%ul) _delete thread[%u], node=%p, pred=%p, lockbegnd=%p, string=%.*s, strlen[%d]\n", 
        tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), node, pred, lockbegnd, strlen, string, strlen);
    // First things first, check if we are NULL 
    if (node == NULL) return NULL;

    assert(node->strlen < 64);

    // the looking for node could be node or node->next or node->child or none of them
    LOG_PRINT("*** thread[%u], lock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
    _nodelock(node, __LINE__, __func__);

    // See if this key is a substring of the string passed in
    cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
    if (cmp == 0) {
        // Yes, either quit, or recur on the children

        // If this key is longer than our search string, the key isn't here
        if (node->strlen > keylen) {
            _nodeunlock(node, __LINE__, __func__);
            if (node == root) {
                pthread_mutex_unlock(&rootlock);
            }
            else if (lockbegnd == NULL) {
                assert(pred);
                _nodeunlock(pred, __LINE__, __func__);
            }
            return NULL;
        } 
        else if (strlen > keylen) {
            //do not unlock any node from pred until _delete return
            if (NULL == lockbegnd)
            {
                if (node == root && node->ip4_address) {
                    pthread_mutex_unlock(&rootlock);
                }
                else if (pred && node->ip4_address) {
                        _nodeunlock(pred, __LINE__, __func__);
                }
                else if (pred && 0 == node->ip4_address){
                    lockbegnd = pred;
                }
                else if (node == root && 0 == node->ip4_address) {
                    lockbegnd = root;
                }
                else {
                    assert(0);
                }
            }
            ///////////////////////////cosider later ////////////////////////////////
            struct trie_node *found =  _delete(node->children, node, lockbegnd, string, strlen - keylen);
            if (found) {
                if (found == lockbegnd && found != root) {
                    assert(found->ip4_address);
                    _nodeunlock(found, __LINE__, __func__);
                    return NULL;
                }
                else if (found == lockbegnd && found == root)
                {
                    //never come here, the last _delete will return when found = root->children
                    assert(0);
                    pthread_mutex_unlock(&rootlock);
                    return NULL;
                }
                /* If the node doesn't have children, delete it.
                 * Otherwise, keep it around to find the kids */
                if (found->children == NULL && found->ip4_address == 0) {
                    assert(node->children == found);
                    node->children = found->next;
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, found->strlen, found->key, found);
                    _nodeunlock(found, __LINE__, __func__);
                    delete_leaf(found);
                }
                else {
                    _nodeunlock(found, __LINE__, __func__);
                }

                /* Delete the root node if we empty the tree */ 
                //如果node之前的节点全部被删除了，则root指向了node，此时会造成对rootlock的重复解锁
                if (node == root && node->children == NULL && node->ip4_address == 0) {
                    root = node->next;
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                    // after this, _delete calling finished, return to delete
                    _nodeunlock(node, __LINE__, __func__);
                    delete_leaf(node);
                    pthread_mutex_unlock(&rootlock);
                }else if (node == root){
                    // after this, _delete calling finished, return to delete
                    _nodeunlock(node, __LINE__, __func__);
                    if (lockbegnd == root && root->ip4_address == 0) {
                        pthread_mutex_unlock(&rootlock);
                    }
                }

                return node; /* Recursively delete needless interior nodes */
            } 
            else {
                if (lockbegnd) {
                    _nodeunlock(node, __LINE__, __func__);
                    if (node == root && root->ip4_address == 0) {
                        assert(root == lockbegnd);
                        pthread_mutex_unlock(&rootlock);
                    }
                    else if (pred && pred == lockbegnd) {
                        //If pred != root, then when pred is lock, lockbend is still NULL
                        if (pred != root || (pred == root && root->ip4_address)) {
                            _nodeunlock(pred, __LINE__, __func__);
                        }
                    }
                }
                return NULL;
            }
            ///////////////////////////cosider later ////////////////////////////////
        }
        else {
            assert (strlen == keylen);
            /* We found it! Clear the ip4 address and return. */
            if (node->ip4_address) {
                node->ip4_address = 0;

                /* Delete the root node if we empty the tree */
                if (node == root && node->children == NULL && node->ip4_address == 0) {
                    root = node->next;
                    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                    _nodeunlock(node, __LINE__, __func__);
                    delete_leaf(node);
                    pthread_mutex_unlock(&rootlock);
                    return (struct trie_node *) 0x100100; /* XXX: Don't use this pointer for anything except 
                                                           * comparison with NULL, since the memory is freed.
                                                           * Return a "poison" pointer that will probably 
                                                           * segfault if used.
                                                           */
                }
                
                return node;
            } 
            else {
                /* Just an interior node with no value */
                LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, node->strlen, node->key, node);
                _nodeunlock(node, __LINE__, __func__);
                if (node == root) {
                    pthread_mutex_unlock(&rootlock);
                }else if (pred && lockbegnd == NULL){
                    _nodeunlock(pred, __LINE__, __func__);
                }
                //pred will be unlock by the up caller
                //if (pred) {
                //    LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, pred->strlen, pred->key, pred);
                //    _nodeunlock(pred, __LINE__, __func__);
                //}
                return NULL;
            }
        }

    } 
    else if (cmp < 0) {
        // No, look right (the node's key is "less" than  the search key)
        if (NULL == lockbegnd)
        {
            if (node == root && node->ip4_address) {
                pthread_mutex_unlock(&rootlock);
            }
            else if (pred && node->ip4_address) {
                    _nodeunlock(pred, __LINE__, __func__);
            }
            else if (pred && 0 == node->ip4_address){
                lockbegnd = pred;
            }
            else if (node == root && 0 == node->ip4_address) {
                lockbegnd = root;
            }
            else {
                assert(0);
            }
        }
        struct trie_node *found = _delete(node->next, node, lockbegnd, string, strlen);
        if (found) {
            if (found == lockbegnd && found != root) {
                assert(found->ip4_address);
                _nodeunlock(found, __LINE__, __func__);
                return NULL;
            }
            else if (found == lockbegnd && found == root)
            {
                //never come here, the last _delete will return when found = root->next
                assert(0);
                pthread_mutex_unlock(&rootlock);
                return NULL;
            }
            /* If the node doesn't have children, delete it.
             * Otherwise, keep it around to find the kids */
            if (found->children == NULL && found->ip4_address == 0) {
                assert(node->next == found);
                node->next = found->next;
                LOG_PRINT("*** thread[%u], Unlock: %d, %.*s, node[%p] ***\n", (unsigned int)pthread_self(), __LINE__, found->strlen, found->key, found);
                _nodeunlock(found, __LINE__, __func__);
                delete_leaf(found);
            }
            else {
                _nodeunlock(found, __LINE__, __func__);
            }

            if (node == root) {
                assert(root->children || root->ip4_address);
                _nodeunlock(node, __LINE__, __func__);
                if (lockbegnd == root && root->ip4_address == 0) {
                    pthread_mutex_unlock(&rootlock);
                }
            }

            return node; /* Recursively delete needless interior nodes */
        }
        else {
            if (lockbegnd) {
                _nodeunlock(node, __LINE__, __func__);
                if (node == root && root->ip4_address == 0) {
                    assert(root == lockbegnd);
                    pthread_mutex_unlock(&rootlock);
                }
                else if (pred && pred == lockbegnd) {
                    //If pred != root, then when pred is lock, lockbend is still NULL
                    if (pred != root || (pred == root && root->ip4_address)) {
                        _nodeunlock(pred, __LINE__, __func__);
                    }
                }
            }
            return NULL;
        }
    }
    else {
        _nodeunlock(node, __LINE__, __func__);
        if (node == root) {
            pthread_mutex_unlock(&rootlock);
        }else if (pred && lockbegnd == NULL){
            _nodeunlock(pred, __LINE__, __func__);
        }
        // Quit early
        return NULL;
    }

}

int delete  (const char *string, size_t strlen) {
    struct timespec tm;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
    LOG_PRINT2("*** 1:tm (%ul.%ul) delete thread[%u], string=%.*s, strlen[%d]\n", 
        tm.tv_sec, tm.tv_nsec, (unsigned int)pthread_self(), strlen, string, strlen);
    // Skip strings of length 0
    if (strlen == 0)
      return 0;
    
    pthread_mutex_lock(&rootlock);
    return (NULL != _delete(root, NULL, NULL, string, strlen));
}


void _print (struct trie_node *node) {
    printf ("Node at %p.  Key %.*s, IP %d.  Next %p, Children %p, islocked=%d\n", 
                node, node->strlen, node->key, node->ip4_address, node->next, node->children, node->islocked);
    if (node->children)
      _print(node->children);
    if (node->next)
      _print(node->next);
}

void print() {
    printf ("Root is at %p\n", root);
    /* Do a simple depth-first search */
    if (root)
      _print(root);
}

void LogInit(const char *logname)
{
    assert(logname);
    g_logfp = fopen(logname, "a+");
    assert(g_logfp);

    return;
}

void LogClose()
{
    if (g_logfp) {
        fclose(g_logfp);
        g_logfp = NULL;
    }   
    return;
}

void LogPrint(const char *fmt, ...)
{
    assert(g_logfp);

    va_list valist;
    va_start(valist, fmt);
    vfprintf(g_logfp, fmt, valist);
    fflush(g_logfp);
    va_end(valist);
    return;
}

#if 0
int main()
{
    LogInit("log.txt");
    //LogPrint("i=%d, x=%d, str=%s", 1, 2, "helloworld");
    //LOG_PRINT("i=%d, x=%d, str=%s\n", 1, 2, "helloworld");
    LogClose();
    return 0;
}
#endif

