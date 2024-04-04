int main()
{
#ifdef CBMC
    unsigned int x = nondet_uint();
    __CPROVER_assume(x < 5);

    if(x > 4000000000) {
        assert(x == 10);
    }
    
#endif

    return 0;
}