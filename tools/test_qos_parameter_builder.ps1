$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$errors = $null
$tokens = $null
$program = [System.Management.Automation.Language.Parser]::ParseFile($env:KSWORD_QOS_PROGRAM, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$builder = $program.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'BuildPolicyParameters' }, $true)
if (-not $builder) { throw 'Production parameter builder not found.' }
. ([scriptblock]::Create($builder.Extent.Text))

# Local parameter-validation mocks match the installed Microsoft CDXML. No
# provider module is imported and no New/Set/Remove-NetQosPolicy is invoked.
function Invoke-NewPolicySchema {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name, [string]$PolicyStore, [string]$NetworkProfile,
        [ValidateNotNullOrEmpty()][string]$AppPathNameMatchCondition,
        [uint64]$ThrottleRateActionBitsPerSecond,
        [ValidateRange(0,63)][sbyte]$DSCPAction,
        [ValidateRange(0,7)][sbyte]$PriorityValue8021Action,
        [ValidateRange(0,3)][uint32]$IPProtocolMatchCondition,
        [ValidateRange(0,255)][uint32]$Precedence,
        [ValidateNotNullOrEmpty()][string]$IPSrcPrefixMatchCondition,
        [ValidateNotNullOrEmpty()][string]$IPDstPrefixMatchCondition,
        [ValidateRange(1,65535)][uint16]$IPSrcPortStartMatchCondition,
        [ValidateRange(1,65535)][uint16]$IPSrcPortEndMatchCondition,
        [ValidateRange(1,65535)][uint16]$IPDstPortStartMatchCondition,
        [ValidateRange(1,65535)][uint16]$IPDstPortEndMatchCondition
    )
    return [hashtable]$PSBoundParameters
}
function Invoke-SetPolicySchema {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name, [string]$PolicyStore, [string]$NetworkProfile,
        [AllowNull()][string]$AppPathNameMatchCondition,
        [uint64]$ThrottleRateActionBitsPerSecond,
        [ValidateRange(-1,63)][sbyte]$DSCPAction,
        [ValidateRange(-1,7)][sbyte]$PriorityValue8021Action,
        [ValidateRange(0,3)][uint32]$IPProtocolMatchCondition,
        [ValidateRange(0,255)][uint32]$Precedence,
        [AllowNull()][string]$IPSrcPrefixMatchCondition,
        [AllowNull()][string]$IPDstPrefixMatchCondition,
        [uint16]$IPSrcPortStartMatchCondition, [uint16]$IPSrcPortEndMatchCondition,
        [uint16]$IPDstPortStartMatchCondition, [uint16]$IPDstPortEndMatchCondition
    )
    return [hashtable]$PSBoundParameters
}
function Check([bool]$value, [string]$message) { if (-not $value) { throw $message } }
$request = [pscustomobject]@{ id='KSword.QoS.{12345678-1234-1234-1234-123456789abc}';applicationPath='C:\Program Files\app.exe';bitsPerSecond='8192';dscp=-1;priority8021=-1;protocol=0;precedence=127;sourcePrefix='';destinationPrefix='';sourcePortStart=0;sourcePortEnd=0;destinationPortStart=0;destinationPortEnd=0 }
$new = BuildPolicyParameters $request $false
$accepted = Invoke-NewPolicySchema @new
foreach ($key in @('IPSrcPortStartMatchCondition','IPSrcPortEndMatchCondition','IPDstPortStartMatchCondition','IPDstPortEndMatchCondition','DSCPAction','PriorityValue8021Action','IPSrcPrefixMatchCondition','IPDstPrefixMatchCondition')) { Check (-not $accepted.ContainsKey($key)) "New unexpectedly supplied $key" }
Check ($accepted.ThrottleRateActionBitsPerSecond -eq 8192) 'New lost its throttle rate.'
$set = BuildPolicyParameters $request $true
$accepted = Invoke-SetPolicySchema @set
foreach ($key in @('IPSrcPortStartMatchCondition','IPSrcPortEndMatchCondition','IPDstPortStartMatchCondition','IPDstPortEndMatchCondition')) { Check ($accepted.ContainsKey($key) -and $accepted[$key] -eq 0) "Set did not clear $key" }
Check ($accepted.DSCPAction -eq -1 -and $accepted.PriorityValue8021Action -eq -1) 'Set did not clear marking actions.'
$new.IPDstPortStartMatchCondition = [uint16]0
$rejected = $false
try { [void](Invoke-NewPolicySchema @new) } catch { $rejected = $true }
Check $rejected 'The local CDXML validation mock must reject an explicitly supplied zero New port.'
$request.protocol=1;$request.destinationPrefix='2001:db8::/48';$request.destinationPortStart=443;$request.destinationPortEnd=443;$request.dscp=46;$request.priority8021=5
$parameters = BuildPolicyParameters $request $false
$accepted = Invoke-NewPolicySchema @parameters
Check ($accepted.IPDstPortStartMatchCondition -eq 443 -and $accepted.IPDstPortEndMatchCondition -eq 443 -and $accepted.DSCPAction -eq 46) 'Explicit New conditions were lost.'
$request.bitsPerSecond='0';$request.applicationPath=''
$parameters = BuildPolicyParameters $request $false
$accepted = Invoke-NewPolicySchema @parameters
Check (-not $accepted.ContainsKey('ThrottleRateActionBitsPerSecond') -and -not $accepted.ContainsKey('AppPathNameMatchCondition')) 'New global marking policy should omit empty image/rate.'
Write-Output 'QOS_PARAMETER_BUILDER=PASS new_omits_any_ports_set_clears_zero_cdxml_schema provider_mutations=0'
