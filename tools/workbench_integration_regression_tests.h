#pragma once
#include <functional>

// 调用生产宿主/比较模型/汇编核心，只使用内存快照和已知指令，不访问真实目标。
void RunWorkbenchIntegrationRegressionTests(const std::function<void(bool, const char*)>& require);
