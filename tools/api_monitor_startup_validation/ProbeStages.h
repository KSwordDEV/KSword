#pragma once
#include <Windows.h>

struct ProbeStages {
    volatile LONG tls, constructor, main;
    volatile LONG tlsWrite, constructorWrite, mainWrite;
    volatile LONG bootstrapLoaded, bootstrapInstalled, bootstrapBeforeTls;
    volatile LONG tlsCaptured, constructorCaptured, mainCaptured;
};
