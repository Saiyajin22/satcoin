#include <time.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    int x = 0;
    srand(time(NULL)); // Initialization, should only be called once.
    for(int i = 0; i < 1000000; i++) {
        int r = rand();
        if (x == r) {
            printf("same number twice in a row. value of r: %d, value of x: %d\n", r, x);
            break;
        }
        x = r;
        printf("random num: %d\n", r);
    }
    

    return 0;
}