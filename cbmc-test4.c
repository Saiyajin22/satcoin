#include <assert.h>
#include <stdio.h>

int plusTen(int num) {
    return num += 10;
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