#pragma once
namespace ksword::ark {
// Installs typed managed-policy callbacks; it does not open/load the driver.
// Each policy operation opens its own silent DriverClient on the worker.
void InstallDriverNetworkPolicies();
}
