#pragma once

// NativeExecutionFixture.asm 导出的固定指令标签。这里只使用地址，C++ 侧不实现这些函数体。
extern "C" void FixtureEnter();
extern "C" unsigned char FixtureNop;
extern "C" unsigned char FixtureCall;
extern "C" unsigned char FixtureAfterCall;
extern "C" unsigned char FixtureCalleeEntry;
