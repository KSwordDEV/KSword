. "$PSScriptRoot\Test-KSwordCliR3-window-capture.ps1"
Assert ((Invoke-Cli @('help','window','capture','set')).Contains('shared WindowListCapture source') -and (Invoke-Cli @('help','window','capture','query')).Contains('mode/display/error')) 'Shared list adapter source/display fields documented in both leaves'
if($InGuest){
 $originalCli=$Cli;$Cli=Join-Path (Split-Path -Parent $Cli) 'R3CaptureRunner.exe'
 try{foreach($mode in @('none','monitor','exclude')){
  $result=(Invoke-Cli @('window','capture','set','--hwnd','self','--pid','self','--tid','self','--creation-time','self','--thread-creation-time','self','--mode',$mode,'--json') 0)|ConvertFrom-Json
  Assert ($result.data.source -eq 'shared WindowListCapture; SetWindowDisplayAffinity + readback' -and $result.data.verified -and $result.data.after.display -match 'WDA_' -and $result.data.display.Contains($result.data.after.display)) 'Production list adapter actual set/readback/label, no message-derived success'
 }}finally{$Cli=$originalCli}
}
