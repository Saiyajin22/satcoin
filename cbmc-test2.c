#include <assert.h>

int main() {

    unsigned int x = 0;
    for(int i = 0; i < 100; ++i) {
        x++;
    }

    #ifdef CBMC
        x = nondet_uint();
        __CPROVER_assume(x < 6 && x > 1);
        // __CPROVER_assume(x == 3);
    #endif
    // x = 2;
    assert(x == 5);
    #ifdef CBMC
        // __CPROVER_assume(x < 30);
    #endif

    return 0;
}