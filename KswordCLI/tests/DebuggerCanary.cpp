#include <Windows.h>
#include <cstdio>

volatile unsigned long long debuggerCanary = 0x1122334455667788ULL;

int main() {
    std::printf("%llu\n", static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(&debuggerCanary)));
    std::fflush(stdout);
    Sleep(90000);
    return 0;
}
