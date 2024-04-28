#include <assert.h>
#include <stdio.h>

int plusTen(int num) {
    return num += 10;
}

unsigned long long factorial(unsigned int n)
{
    if (n == 0)
    {
        return 1;
    }
    else
    {
        return n * factorial(n - 1);
    }
}

unsigned int sha_h[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

void sha_initstate(unsigned int *state)
{
    int n;

    for (n = 0; n < 8; n++)
    {
        *state = sha_h[n];
        state++;
    }
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
    unsigned int state[8];
    sha_initstate((unsigned int *)&state);

    #ifdef CBMC
        x = nondet_uint();
        __CPROVER_assume(x > 0 && x <= 2000);
    #endif

    // printf("x: %d\n", x);
    state[7] = x;
    printf("state[7]: %d\n", state[7]);

    

#ifdef CBMC
        // __CPROVER_assume(
        //     (unsigned char)((state[7] >> 0) & 0xff) == 0x00 &&
        //     (unsigned char)((state[7] >> 8) & 0xff) == 0x00 &&
        //     (unsigned char)((state[7] >> 16) & 0xff) == 0x00);
        __CPROVER_assume(state[7] > 1992);
    #endif

    // x = plusTen(x);
    // if (x > 2008)
    // {
    //     assert(0);
    // }

    assert(0);
    return 0;
}