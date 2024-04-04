#include <assert.h>

int main()
{
    int x;
    #ifdef CBMC
        x = nondet_uint();
    #endif
  
  __CPROVER_assume(x > 0);
//   __CPROVER_assume(x < 0);
  assert(0 == 1);
}