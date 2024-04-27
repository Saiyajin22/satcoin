#include <assert.h>

/*This program will be SUCCESSFUL for CBMC
Because the __CPROVER_assume(i > 50); will evaluate to false, as the first iteration of the for loop will have i with value 0
As this assumption false, the rest of the program will be skipped from execution!
*/
int main() {

    unsigned int x = 0;
    unsigned int y = 100;
    for(int i = 0; i < 100; ++i) {
        #ifdef CBMC
            // x++;
            // x = nondet_uint();
            // __CPROVER_assume(x < 6 && x > 1);
            __CPROVER_assume(i > 50);
            // __CPROVER_assume(x == 3);
        #endif
        y += i;
        assert(y == 20);
        assert(0);
    }


    for(int i = 0; i < 3000; ++i) {
        assert(0);
    }

    for (int j = 0; j < 3000; ++j)
    {
        assert(0);
    }

    // __CPROVER_assume(x == 4);
    // assert(x == 5);

    
    // x = 2;
    // assert(x == 5);
    // #ifdef CBMC
    //     // __CPROVER_assume(x < 30);
    // #endif

    assert(0);
    return 0;
}