#include <assert.h>
#include <stdio.h>

int plusTen(int num) {
    return num += 10;
}


unsigned long long fib(int n, unsigned long long memo[])
{
    if (n <= 1)
    {
        return n;
    }
    if (memo[n] != 0)
    {
        return memo[n];
    }
    memo[n] = fib(n - 1, memo) + fib(n - 2, memo);
    return memo[n];
}

int main()
{
    unsigned int x = 0;
    unsigned int changeable_var = 0;

    #ifdef CBMC
        x = nondet_uint();
        __CPROVER_assume(x > 0 && x <= 1993);
    #endif

#ifdef CBMC
        __CPROVER_assume(state[7] > 1992);
    #endif


    printf("end");
    assert(0);
    return 0;
}