#include <assert.h>

int main() {

    unsigned int x = 0;
    for(int i = 0; i < 100; ++i) {
        #ifdef CBMC
            // x++;
            x = nondet_uint();
            __CPROVER_assume(x < 6 && x > 1);
            // __CPROVER_assume(x == 3);
        #endif
        assert(x == 5);
    }

    // __CPROVER_assume(x == 4);
    // assert(x == 5);

    
    // x = 2;
    // assert(x == 5);
    // #ifdef CBMC
    //     // __CPROVER_assume(x < 30);
    // #endif

    return 0;
}