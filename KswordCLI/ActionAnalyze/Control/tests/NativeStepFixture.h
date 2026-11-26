#pragma once

// Labels in the fixed benign AMD64 sequence implemented by NativeStepFixture.asm.
// They are code addresses, not C++ bodies; only their addresses are used.
extern "C" void FixtureStepCallRun();
extern "C" unsigned char FixtureStepCallRunAfter;
extern "C" void FixtureStepRun();
extern "C" unsigned char FixtureStepNop;
extern "C" unsigned char FixtureStepCall;
extern "C" unsigned char FixtureStepAfterCall;
extern "C" unsigned char FixtureStepUnknown;
extern "C" unsigned char FixtureStepRet;
extern "C" unsigned char FixtureStepCalleeEntry;
