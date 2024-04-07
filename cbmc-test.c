#include <assert.h>

int main() {

    int y = 25;

    for (int i = 0; i < 10; i++) {
        y++;
        __CPROVER_assume(y > 30);
        assert(y > 3000);
    }

    return 0;
}