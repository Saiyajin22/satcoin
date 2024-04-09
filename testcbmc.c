#include <assert.h>
#include <string.h>

int main()
{
    unsigned int x = 22;
    #ifdef CBMC
        x = nondet_uint();

        __CPROVER_assume(x < 10 && x > 0);

        assert(x < 10);
    #endif
}