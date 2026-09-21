# General SVM entry/exit smoke test only; never claims an inner OS boot.
[CmdletBinding()]
param([ValidateSet(1,8)][int]$Vcpu=1,
      [ValidateRange(1,1000)][int]$Cycles=1)
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Start-GuestNestedProbe.ps1') -Vcpu $Vcpu -Cycles $Cycles -GeneralResident
