#include <assert.h>
#include <stdio.h>

int plusTen(int num) {
    return num += 10;
}

int main()
{
    unsigned int x = 0;

    #ifdef CBMC
        x = nondet_uint();
        __CPROVER_assume(x > 0 && x < 1000);
    #endif

    x = plusTen(x);
    if (x > 40) {
        assert(0);
    }
    printf("x: %d\n", x);


    // assert(0);
    return 0;
}