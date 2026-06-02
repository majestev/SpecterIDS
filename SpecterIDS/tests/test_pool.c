#include "pool.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    ids_pool_t pool;
    int *first;
    int *second;

    assert(ids_pool_init(&pool, 1, sizeof(int)) == 0);

    first = (int *)ids_pool_try_acquire(&pool);
    assert(first != NULL);
    assert(ids_pool_in_use(&pool) == 1);
    *first = 42;
    assert(ids_pool_try_acquire(&pool) == NULL);
    assert(ids_pool_failed_acquires(&pool) == 1);

    ids_pool_release(&pool, first);
    assert(ids_pool_in_use(&pool) == 0);
    ids_pool_release(&pool, first);
    assert(ids_pool_invalid_releases(&pool) == 1);
    second = (int *)ids_pool_acquire(&pool);
    assert(second != NULL);
    assert(*second == 0);

    ids_pool_release(&pool, second);
    assert(ids_pool_available(&pool) == 1);
    assert(ids_pool_capacity(&pool) == 1);
    ids_pool_destroy(&pool);
    puts("test_pool: ok");
    return 0;
}
