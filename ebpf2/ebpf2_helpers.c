#include <sys/resource.h>
#include <unistd.h>

int bump_memlock_rlimit(void)
{
        struct rlimit rlim_new = {
                .rlim_cur       = RLIM_INFINITY,
                .rlim_max       = RLIM_INFINITY,
        };
        
        return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}
