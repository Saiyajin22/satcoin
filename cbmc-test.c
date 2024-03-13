int main() {

    int y = 25;

    #ifdef CBMC
        int x = nondet_uint();

        __CPROVER_assume(x > 0 && x < 1000);

        x += 2;

        y += x;

        assert(y % 2 == 0);
    #endif

    return 0;
}