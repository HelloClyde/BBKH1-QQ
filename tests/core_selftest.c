#include "selftest.h"
#include <stdio.h>
int main(void)
{
    h1qq_core_results result={0};
    int ok=h1qq_core_selftest(&result);
    printf("{\"passed\":%s,\"checks\":%u,\"failed\":%u}\n",ok&&!result.failed?"true":"false",result.checks,result.failed);
    return ok&&!result.failed?0:1;
}
