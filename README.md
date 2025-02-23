# Este script está hospedado em https://get.activated.win para https://massgrave.dev
# Créditos ao u4hy

if ($ExecutionContext.SessionState.LanguageMode.value__ -ne 0) {
    $ExecutionContext.SessionState.LanguageMode
    Write-Host "O Windows PowerShell não está rodando no Modo de Linguagem Completa."
    Write-Host "Ajuda - https://massgrave.dev/fix_powershell" -ForegroundColor White -BackgroundColor Blue
    return
}

function VerificarAntivirus3rd {
    $avList = Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Where-Object { $_.displayName -notlike '*windows*' } | Select-Object -ExpandProperty displayName
    if ($avList) {
        Write-Host 'Antivírus de terceiros pode estar bloqueando o script - ' -ForegroundColor White -BackgroundColor Blue -NoNewline
        Write-Host " $($avList -join ', ')" -ForegroundColor DarkRed -BackgroundColor White
    }
}

function VerificarArquivo { 
    param ([string]$CaminhoArquivo) 
    if (-not (Test-Path $CaminhoArquivo)) { 
        VerificarAntivirus3rd
        Write-Host "Falha ao criar o arquivo MAS na pasta temp, abortando!"
        Write-Host "Ajuda - https://massgrave.dev/troubleshoot" -ForegroundColor White -BackgroundColor Blue
        throw 
    } 
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$URLs = @(
    'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/60c99742ce9ff1c675c6e381e17b0f4ccf1a57bd/MAS/All-In-One-Version-KL/MAS_AIO.cmd',
    'https://dev.azure.com/massgrave/Microsoft-Activation-Scripts/_apis/git/repositories/Microsoft-Activation-Scripts/items?path=/MAS/All-In-One-Version-KL/MAS_AIO.cmd&versionType=Commit&version=60c99742ce9ff1c675c6e381e17b0f4ccf1a57bd',
    'https://git.activated.win/massgrave/Microsoft-Activation-Scripts/raw/commit/60c99742ce9ff1c675c6e381e17b0f4ccf1a57bd/MAS/All-In-One-Version-KL/MAS_AIO.cmd'
)

foreach ($URL in $URLs | Sort-Object { Get-Random }) {
    try { $response = Invoke-WebRequest -Uri $URL -UseBasicParsing; break } catch {}
}

if (-not $response) {
    VerificarAntivirus3rd
    Write-Host "Falha ao recuperar o MAS de qualquer um dos repositórios disponíveis, abortando!"
    Write-Host "Ajuda - https://massgrave.dev/troubleshoot" -ForegroundColor White -BackgroundColor Blue
    return
}

# Verificar integridade do script
$releaseHash = '16F0FFCDD242A0D514B9D96AE1535F48A2E2811D45A8094E98BB0A26EA2FEBBA'
$stream = New-Object IO.MemoryStream
$writer = New-Object IO.StreamWriter $stream
$writer.Write($response)
$writer.Flush()
$stream.Position = 0
$hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) -replace '-'
if ($hash -ne $releaseHash) {
    Write-Warning "Hash ($hash) incompatível, abortando!`nReporte esse problema em https://massgrave.dev/troubleshoot"
    $response = $null
    return
}

# Verificar AutoRun no registro que pode criar problemas com o CMD
$paths = "HKCU:\SOFTWARE\Microsoft\Command Processor", "HKLM:\SOFTWARE\Microsoft\Command Processor"
foreach ($path in $paths) { 
    if (Get-ItemProperty -Path $path -Name "Autorun" -ErrorAction SilentlyContinue) { 
        Write-Warning "Registro Autorun encontrado, o CMD pode falhar! `nCopie e cole manualmente o seguinte comando para corrigir...`nRemove-ItemProperty -Path '$path' -Name 'Autorun'"
    } 
}

$rand = [Guid]::NewGuid().Guid
$isAdmin = [bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544')
$CaminhoArquivo = if ($isAdmin) { "$env:SystemRoot\Temp\MAS_$rand.cmd" } else { "$env:USERPROFILE\AppData\Local\Temp\MAS_$rand.cmd" }
Set-Content -Path $CaminhoArquivo -Value "@::: $rand `r`n$response"
VerificarArquivo $CaminhoArquivo

$env:ComSpec = "$env:SystemRoot\system32\cmd.exe"
$chkcmd = & $env:ComSpec /c "echo CMD está funcionando"
if ($chkcmd -notcontains "CMD está funcionando") {
    Write-Warning "cmd.exe não está funcionando.`nReporte esse problema em https://massgrave.dev/troubleshoot"
}
Start-Process -FilePath $env:ComSpec -ArgumentList "/c """"$CaminhoArquivo"" $args""" -Wait
VerificarArquivo $CaminhoArquivo

$CaminhosArquivos = @("$env:SystemRoot\Temp\MAS*.cmd", "$env:USERPROFILE\AppData\Local\Temp\MAS*.cmd")
foreach ($CaminhoArquivo in $CaminhosArquivos) { Get-Item $CaminhoArquivo | Remove-Item }
