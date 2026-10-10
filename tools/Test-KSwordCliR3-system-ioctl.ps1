$help=Invoke-Cli @('help','system','ioctl','decode')
Assert ($help.Contains('--code') -and (Invoke-Cli @('system','ioctl','decode','--help')) -eq $help) 'IOCTL decode leaf help'
Assert (!(Invoke-Cli @('system','ioctl','help')).Contains('--code')) 'IOCTL decode intermediate help'
foreach($bad in @(
 @('system','ioctl','decode','--json'),
 @('system','ioctl','decode','--code','-1','--json'),
 @('system','ioctl','decode','--code','4294967296','--json'),
 @('system','ioctl','decode','--code','0x100000000','--json'),
 @('system','ioctl','decode','--code','xyz','--json'),
 @('system','ioctl','decode','--code','0x','--json'),
 @('system','ioctl','decode','--code','1.0','--json'),
 @('system','ioctl','decode','--code','1','--backend','r0','--json'),
 @('system','ioctl','decode','--code','1','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'IOCTL numeric validation'}
foreach($sample in @(0,1,3,4,8192,16384,65536,2236416,2147483648,4294967295)){
 [uint32]$value=$sample
 $result=(Invoke-Cli @('system','ioctl','decode','--code',$value.ToString(),'--json'))|ConvertFrom-Json
 $data=$result.data;$device=($value -shr 16) -band 65535;$function=($value -shr 2) -band 4095;$access=($value -shr 14) -band 3;$method=$value -band 3
 Assert ($data.codeDecimal -eq $value -and $data.code -eq ('0x'+$value.ToString('x')) -and $data.normalizedCode -eq ('0x'+$value.ToString('X8'))) 'IOCTL full uint32/code formats'
 Assert ($data.deviceType -eq ('0x'+$device.ToString('x')) -and $data.function -eq ('0x'+$function.ToString('x')) -and $data.access -eq $access -and $data.method -eq $method) 'Independent CTL_CODE masks'
 Assert ($data.common -eq (($value -band 2147483648) -ne 0) -and $data.custom -eq (($value -band 8192) -ne 0)) 'Independent common/custom bit flags'
}
$decimal=(Invoke-Cli @('system','ioctl','decode','--code','222000','--json'))|ConvertFrom-Json
Assert ($decimal.data.codeDecimal -eq 222000) 'Unprefixed CLI numbers remain decimal'
$hex=(Invoke-Cli @('system','ioctl','decode','--code','0x222000','--json'))|ConvertFrom-Json
Assert ($hex.data.codeDecimal -eq 2236416 -and $hex.data.methodName -eq 'METHOD_BUFFERED' -and $hex.data.accessName -eq 'FILE_ANY_ACCESS') 'Hex input and standard macro names'
Assert ((Invoke-Cli @('system','ioctl','decode','--code','0xffffffff')).Contains('methodName: METHOD_NEITHER')) 'IOCTL readable text output'
