# ============================================================
#  Buscador de Sesiones - Visor de Eventos Windows
#  Version final: XPath + nombre exacto, maxima velocidad
# ============================================================

Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName PresentationFramework

$AutoDomain = $env:USERDOMAIN

$User = [Microsoft.VisualBasic.Interaction]::InputBox(
    "Nombre de usuario (dominio detectado: $AutoDomain):",
    "Buscador de Sesiones",
    "Administrador"
)
if ([string]::IsNullOrWhiteSpace($User)) { exit }

$DaysInput = [Microsoft.VisualBasic.Interaction]::InputBox(
    "Dias hacia atras (1-365):",
    "Rango de busqueda",
    "20"
)

$temp = 0
$Days = if ([int]::TryParse($DaysInput, [ref]$temp)) {
    [Math]::Max(1, [Math]::Min($temp, 365))
} else { 7 }

Write-Host "Buscando sesiones para '$User' en los ultimos $Days dias..." -ForegroundColor Cyan
Write-Host "Dominio detectado: $AutoDomain" -ForegroundColor DarkCyan

try {
    $StartTimeFmt = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")

    # Filtro XPath: corre dentro del motor de Windows Event Log.
    # Filtra por EventID, fecha y nombre exacto de usuario antes de enviar datos a PowerShell.
    $XPath = @"
*[System[
    (EventID=4624 or EventID=4634)
    and TimeCreated[@SystemTime>='$StartTimeFmt']
  ]
  and EventData[
    Data[@Name='TargetUserName'] = '$User'
  ]
]
"@

    $Eventos = Get-WinEvent -LogName Security -FilterXPath $XPath -ErrorAction Stop |
        Select-Object TimeCreated,
            @{Name='Accion';     Expression={ if ($_.Id -eq 4624) { 'ENTRADA' } else { 'SALIDA' } }},
            @{Name='Usuario';    Expression={ $_.Properties[5].Value }},
            @{Name='Dominio';    Expression={ $_.Properties[6].Value }},
            @{Name='Tipo_Logon'; Expression={ $_.Properties[8].Value }},
            @{Name='IP_Origen';  Expression={
                if ($_.Id -eq 4624) { $_.Properties[18].Value } else { 'N/A' }
            }}

    if (-not $Eventos) {
        [System.Windows.MessageBox]::Show(
            "No se encontraron registros para '$User' en los ultimos $Days dias.`n`n" +
            "Verifique si el historial del Visor de Eventos llega hasta esa fecha.",
            "Sin resultados"
        )
    } else {
        $Total = @($Eventos).Count
        Write-Host "Se encontraron $Total evento(s). Abriendo grilla..." -ForegroundColor Green

        $Eventos | Out-GridView -Title "Sesiones de '$User' - Ultimos $Days dias ($Total registros)"

        $Exportar = [Microsoft.VisualBasic.Interaction]::MsgBox(
            "Se encontraron $Total registro(s).`n`nDesea exportar los resultados a CSV?",
            [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
            "Exportar resultados"
        )
        if ($Exportar -eq [Microsoft.VisualBasic.MsgBoxResult]::Yes) {
            $Archivo = ".\sesiones_${User}_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
            $Eventos | Export-Csv -Path $Archivo -NoTypeInformation -Encoding UTF8
            Write-Host "Exportado en: $Archivo" -ForegroundColor Green
            [System.Windows.MessageBox]::Show("Archivo guardado en:`n$Archivo", "Exportacion exitosa")
        }
    }

} catch [System.Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        [System.Windows.MessageBox]::Show(
            "No se encontraron registros para '$User' en los ultimos $Days dias.",
            "Sin resultados"
        )
    } else {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        [System.Windows.MessageBox]::Show(
            "Error al acceder al log de Seguridad.`n`nDetalle: $($_.Exception.Message)`n`n" +
            "Asegurese de ejecutar el script como Administrador.",
            "Error"
        )
    }
}
