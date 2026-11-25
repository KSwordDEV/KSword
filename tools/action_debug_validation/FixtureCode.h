#pragma once

// These symbols are labels in a fixed benign AMD64 sequence, not C++ bodies.
extern "C" int FixtureRun(int raiseControlledException);
extern "C" unsigned char FixtureStart;
extern "C" unsigned char FixtureCall;
extern "C" unsigned char FixtureAfterCall;
extern "C" unsigned char FixtureCalleeEntry;
extern "C" unsigned char FixtureEarly;
extern "C" unsigned char FixtureFault;

int RunDebugScenarios();
