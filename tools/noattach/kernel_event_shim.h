#pragma once
#include "kernel_shim.h"
#include "../../shared/driver/KswordArkKernelNoAttachIoctl.h"
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
using FixtureSpinLock = std::mutex;
#define KSPIN_LOCK FixtureSpinLock
using KIRQL = unsigned char;
using KPROCESSOR_MODE = char;
struct FixtureDriver;
using PDRIVER_OBJECT = FixtureDriver*;
using PDRIVER_UNLOAD = void (*)(PDRIVER_OBJECT);
struct FixtureDriver { PDRIVER_UNLOAD DriverUnload; };
struct KEVENT { HANDLE handle = nullptr; };
#ifndef APC_LEVEL
#define APC_LEVEL 1
#endif
#ifndef DISPATCH_LEVEL
#define DISPATCH_LEVEL 2
#endif
constexpr KPROCESSOR_MODE KernelMode = 0;
constexpr int Executive = 0;
constexpr int IO_NO_INCREMENT = 0;
// Kernel EXCEPTION_RECORD uses NTSTATUS; the user SDK declares DWORD.
struct FixtureExceptionRecord { NTSTATUS ExceptionCode = 0; };
#define EXCEPTION_RECORD FixtureExceptionRecord
#define PEXCEPTION_RECORD FixtureExceptionRecord*
inline thread_local KIRQL fixtureIrql = 0;
inline void KeAcquireSpinLock(KSPIN_LOCK* lock, KIRQL* old) { lock->lock(); *old = fixtureIrql; fixtureIrql = 2; }
inline void KeReleaseSpinLock(KSPIN_LOCK* lock, KIRQL old) { fixtureIrql = old; lock->unlock(); }
inline KIRQL KeGetCurrentIrql() { return fixtureIrql; }
inline ULONGLONG KeQueryInterruptTime() { return GetTickCount64() * 10000ULL; }
inline void KeClearEvent(KEVENT* event) { ResetEvent(event->handle); }
inline LONG KeSetEvent(KEVENT* event, int, BOOLEAN) { SetEvent(event->handle); return 0; }
inline NTSTATUS KeWaitForSingleObject(KEVENT* event, int, KPROCESSOR_MODE, BOOLEAN, LARGE_INTEGER* timeout)
{
    return WaitForSingleObject(event->handle, static_cast<DWORD>(-timeout->QuadPart / 10000)) == WAIT_OBJECT_0 ? STATUS_SUCCESS : STATUS_TIMEOUT;
}
void* PsGetCurrentThread();
BOOLEAN PsIsThreadTerminating(PETHREAD);
