#include <assert.h>

int main() {

    int y = 25;

    for (int i = 0; i < 10; i++) {
        y+=i;

        #ifdef CBMC
            y = nondet_uint();
        #endif

        if(y > 30) {
            assert(0);
        }
    }

    return 0;
}