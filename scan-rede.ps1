<#
.SYNOPSIS
    Detecta a rede local automaticamente, instala o Nmap se necessario, e a
    escaneia gerando um inventario em CSV. Pensado para rodar de um pen drive
    ou via AnyDesk em qualquer PC, sem precisar informar nada na mao.

.DESCRIPTION
    1. Se elevado, se autoeleva pedindo permissao de Administrador (UAC).
    2. Verifica se o Nmap ja esta instalado; se nao, baixa o instalador oficial
       de nmap.org, confere a assinatura digital, e instala silenciosamente.
    3. Identifica os adaptadores de rede ativos (cabo/Wi-Fi) do PC, ignorando
       adaptadores virtuais (Hyper-V, WSL, VPN, loopback).
    4. Calcula a faixa CIDR de cada rede a partir do IPv4 + mascara de sub-rede.
    5. Roda o Nmap contra cada faixa encontrada.
    6. Salva um CSV com IP, hostname, MAC, fabricante, SO estimado e portas
       abertas de cada dispositivo ativo, na pasta "resultados" ao lado do
       script.

.PARAMETER Rede
    Opcional. Forca uma ou mais faixas CIDR especificas (ex: 10.5.20.0/24) em vez
    de detectar automaticamente. Use se a deteccao automatica escolher a rede
    errada (ex: PC com VPN corporativa ligada). Aceita varias faixas separadas
    por virgula (ex: -Rede 10.5.20.0/24,192.168.1.0/24) - elas sao escaneadas
    em paralelo, uma linha de log por evento de cada faixa.

.PARAMETER Forcar
    Opcional. Roda o scan completo mesmo se a rede detectada ja for conhecida
    (ja escaneada em execucao anterior). Por padrao, redes ja conhecidas sao
    puladas automaticamente (pre-teste rapido) para nao gastar tempo reescaneando
    o que ja foi mapeado - util quando voce esta testando varios cabos/pontos de
    rede em sequencia e so quer parar de verdade onde encontrar algo novo.

.EXAMPLE
    .\scan-rede.ps1
.EXAMPLE
    .\scan-rede.ps1 -Rede 10.5.20.0/24
.EXAMPLE
    .\scan-rede.ps1 -Forcar
#>

param(
    [string[]]$Rede,
    [switch]$Forcar
)

# Normaliza -Rede pra sempre virar uma lista de faixas individuais, independente de
# como chegou: digitado direto no console (10.5.20.0/24,192.168.1.0/24 ja vira array
# por conta do parser do PowerShell) ou passado como uma unica string com virgulas
# (caso do relancamento apos a autoelevacao, que nao faz esse split automatico).
if ($Rede) {
    $Rede = @($Rede | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Mantem a janela aberta no final (sucesso ou erro) quando rodado por duplo-clique/atalho,
# para que mensagens de erro nao "sumam" com o fechamento automatico do console.
function Aguardar-Saida {
    if ($Host.Name -eq 'ConsoleHost') {
        Write-Host ""
        Read-Host "Pressione Enter para fechar"
    }
}

function Get-CaminhoRedesConhecidas {
    return Join-Path $PSScriptRoot "redes_conhecidas.json"
}

function Get-ProximoNumeroRegistro {
    # Numero de registro sequencial (independente do timestamp) para rastrear/auditar
    # execucoes do scanner ao longo do tempo, mesmo em maquinas diferentes. Persistido
    # ao lado do script, igual a memoria de redes conhecidas.
    $caminho = Join-Path $PSScriptRoot "registro_scans.json"
    $ultimo = 0
    if (Test-Path $caminho) {
        try {
            $conteudo = Get-Content $caminho -Raw | ConvertFrom-Json
            $ultimo = [int]$conteudo.UltimoNumero
        } catch {
            Write-Host "Aviso: nao foi possivel ler o contador de registro ($caminho). Reiniciando a partir de 1." -ForegroundColor Yellow
        }
    }

    $numero = $ultimo + 1
    [PSCustomObject]@{ UltimoNumero = $numero } | ConvertTo-Json | Out-File -FilePath $caminho -Encoding UTF8
    return "{0:D6}" -f $numero
}

function Get-NomeComputadorCompleto {
    # Tenta o nome completo (FQDN, ex: PC-TI01.empresa.local) e cai para o nome curto
    # do Windows (ex: PC-TI01) se a maquina nao tiver DNS/dominio configurado.
    try {
        $fqdn = [Net.Dns]::GetHostEntry([Net.Dns]::GetHostName()).HostName
        if ($fqdn) { return $fqdn }
    } catch {
        # Sem resolucao DNS disponivel - segue com o nome curto abaixo.
    }
    return $env:COMPUTERNAME
}

function Invoke-NmapCapturado {
    param([string[]]$NmapArgs)
    # Roda o nmap capturando stdout+stderr juntos, SEM deixar linhas de aviso do
    # proprio nmap (que vao para stderr, ex: "WARNING: No targets were specified")
    # virarem erro fatal do PowerShell. Com $ErrorActionPreference = "Stop" no
    # escopo do script, qualquer linha em stderr de um comando externo com "2>&1"
    # normalmente vira uma excecao - isso e revertido so aqui dentro, localmente.
    $prefAnterior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $script:nmapExe @NmapArgs 2>&1
    } finally {
        $ErrorActionPreference = $prefAnterior
    }
}

function Get-RedesConhecidas {
    $caminho = Get-CaminhoRedesConhecidas
    if (-not (Test-Path $caminho)) { return @() }
    try {
        $conteudo = Get-Content $caminho -Raw | ConvertFrom-Json
        return @($conteudo)
    } catch {
        Write-Host "Aviso: nao foi possivel ler o historico de redes conhecidas ($caminho). Tratando como vazio." -ForegroundColor Yellow
        return @()
    }
}

function Save-RedeConhecida([string]$cidr, [string]$timestamp) {
    $caminho = Get-CaminhoRedesConhecidas
    $lista = @(Get-RedesConhecidas)
    $existente = $lista | Where-Object { $_.CIDR -eq $cidr } | Select-Object -First 1

    if ($existente) {
        $existente.UltimaVez = $timestamp
        $existente.QtdExecucoes = [int]$existente.QtdExecucoes + 1
    } else {
        $lista = @($lista) + [PSCustomObject]@{
            CIDR         = $cidr
            PrimeiraVez  = $timestamp
            UltimaVez    = $timestamp
            QtdExecucoes = 1
        }
    }

    $lista | ConvertTo-Json -Depth 3 | Out-File -FilePath $caminho -Encoding UTF8
}

function Test-Administrador {
    $identidade = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identidade)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Nmap {
    Write-Host "Nmap nao encontrado. Baixando o instalador oficial..." -ForegroundColor Cyan

    $versao = "7.95"
    $url = "https://nmap.org/dist/nmap-$versao-setup.exe"
    $destino = Join-Path $env:TEMP "nmap-$versao-setup.exe"

    try {
        Invoke-WebRequest -Uri $url -OutFile $destino -UseBasicParsing
    } catch {
        throw "Falha ao baixar o Nmap de $url : $($_.Exception.Message). Baixe manualmente em https://nmap.org/download.html e rode o instalador, depois execute este script de novo."
    }

    # Confere se o instalador baixado e assinado digitalmente antes de rodar
    $assinatura = Get-AuthenticodeSignature -FilePath $destino
    $assinanteEsperado = @('Insecure.Com LLC', 'Nmap Project', 'Nmap Software LLC')
    $nomeAssinante = if ($assinatura.SignerCertificate) { $assinatura.SignerCertificate.Subject } else { "(sem certificado)" }
    $assinaturaValida = ($assinatura.Status -eq 'Valid') -and ($assinanteEsperado | Where-Object { $nomeAssinante -match [regex]::Escape($_) })

    if (-not $assinaturaValida) {
        Remove-Item $destino -Force -ErrorAction SilentlyContinue
        throw "O instalador baixado nao tem assinatura digital valida do Nmap Project (Status: $($assinatura.Status) / Assinante: $nomeAssinante). Abortando por seguranca."
    }

    Write-Host "Assinatura digital valida ($nomeAssinante). Instalando silenciosamente..." -ForegroundColor Cyan
    $processo = Start-Process -FilePath $destino -ArgumentList '/S' -Wait -PassThru
    Remove-Item $destino -Force -ErrorAction SilentlyContinue

    if ($processo.ExitCode -ne 0) {
        throw "O instalador do Nmap terminou com codigo de erro $($processo.ExitCode)."
    }

    # Caminhos padrao de instalacao do Nmap no Windows
    $candidatos = @(
        "$env:ProgramFiles\Nmap\nmap.exe",
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
    )
    $instalado = $candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $instalado) {
        throw "A instalacao do Nmap parece ter falhado (executavel nao encontrado em nenhum dos caminhos padrao apos instalar)."
    }

    Write-Host "Nmap instalado em: $instalado" -ForegroundColor Green
    return $instalado
}

# Fabricantes tipicos de equipamento de rede (roteador/switch/AP) - usado para sinalizar
# no CSV dispositivos que podem ser infraestrutura de rede nao mapeada, nao so "um PC".
$FabricantesEquipamentoRede = @(
    'TP-Link', 'TP-LINK', 'Mercusys', 'D-Link', 'DLink', 'Netgear', 'Ubiquiti', 'MikroTik', 'Mikrotik',
    'Cisco', 'Huawei', 'Aruba', 'Ruckus', 'Ruijie', 'Zyxel', 'Tenda', 'Intelbras',
    'Multilaser', 'Linksys', 'Fortinet', 'Juniper', 'H3C', 'Extreme Networks',
    'DrayTek', 'Draytek', 'Actiontec', 'Arris', 'Sagemcom', 'Technicolor', 'Sercomm', 'Askey'
)

function Test-EquipamentoDeRede([string]$fabricante) {
    if (-not $fabricante) { return $false }
    foreach ($f in $FabricantesEquipamentoRede) {
        if ($fabricante -match [regex]::Escape($f)) { return $true }
    }
    return $false
}

# Fabricantes de placa-mae/sistema tipicos de PC/servidor "montado" (nao rede, nao contrato).
$FabricantesPcServidor = @(
    'Gigabyte', 'ASUSTek', 'Asus', 'ASRock', 'Micro-Star', 'MSI', 'Dell', 'Hewlett Packard', 'HP ',
    'Lenovo', 'Supermicro', 'Elitegroup', 'Biostar', 'Intel Corporate'
)

# Fabricantes de contrato/ODM: fabricam placas de rede/hardware para MUITAS marcas diferentes
# (impressoras, roteadores, IoT, notebooks white-label). O tipo real fica ambiguo so pelo OUI.
$FabricantesContratados = @(
    'Foxconn', 'Hon Hai', 'Pegatron', 'Quanta', 'Compal', 'Wistron', 'Flextronics', 'Flex ', 'Jabil'
)

# Fabricantes de chip de rede genericos, usados tanto em PCs quanto em impressoras/equipamentos -
# ambiguo so pelo OUI, so a porta de servico (9100/631/515) confirma se e impressora de verdade.
$FabricantesChipGenerico = @('Realtek Semiconductor', 'Realtek')

function Test-MacLocalmenteAdministrado([string]$mac) {
    # Bit "locally administered" (0x02) do primeiro octeto do MAC. Quando ligado, o endereco
    # nao veio de um OUI de fabricante real - e um MAC gerado/aleatorizado (comum em VMs,
    # celulares com privacidade de MAC ativada, containers, etc.), nao um dispositivo fisico
    # identificavel por fabricante.
    if (-not $mac) { return $false }
    $primeiroOcteto = ($mac -split '[:\-]')[0]
    if (-not $primeiroOcteto) { return $false }
    try {
        $valor = [Convert]::ToByte($primeiroOcteto, 16)
        return (($valor -band 0x02) -ne 0)
    } catch {
        return $false
    }
}

function Get-TipoProvavel([string]$fabricante, [string]$mac, [string]$soEstimado) {
    if (Test-MacLocalmenteAdministrado $mac) {
        return "VM / dispositivo com MAC aleatorio"
    }
    if (-not $fabricante -or $fabricante -match '^\(?desconhecido\)?$|^Unknown$') {
        return "(fabricante nao identificado)"
    }
    foreach ($f in $FabricantesEquipamentoRede) {
        if ($fabricante -match [regex]::Escape($f)) { return "Roteador / AP / Switch" }
    }
    foreach ($f in $FabricantesChipGenerico) {
        if ($fabricante -match [regex]::Escape($f)) { return "Possivel impressora (verificar porta 9100/631/515)" }
    }
    foreach ($f in $FabricantesContratados) {
        if ($fabricante -match [regex]::Escape($f)) { return "Possivel (fabricante de contrato/ODM)" }
    }
    foreach ($f in $FabricantesPcServidor) {
        if ($fabricante -match [regex]::Escape($f)) { return "PC / Servidor" }
    }
    return "Nao classificado"
}

function Confirm-Impressoras {
    param(
        [array]$Linhas,
        [string]$PastaResultados,
        [string]$Timestamp
    )
    # Roda um scan focado nas portas classicas de impressao (9100=RAW/JetDirect, 631=IPP, 515=LPD)
    # so nos hosts cujo fabricante do MAC e ambiguo (chip de rede generico tipo Realtek), para
    # confirmar de verdade se sao impressoras ou apenas PCs com aquele chip de rede onboard.
    $candidatos = @($Linhas | Where-Object { $_.TipoProvavel -like "Possivel impressora*" })
    if ($candidatos.Count -eq 0) { return $Linhas }

    Write-Host ""
    Write-Host "Confirmando $($candidatos.Count) possivel(is) impressora(s) (portas 9100/631/515)..." -ForegroundColor Cyan

    $ips = $candidatos | Select-Object -ExpandProperty IP -Unique
    $logPath = Join-Path $PastaResultados "confirmacao_impressoras_$Timestamp.txt"

    try {
        # -Pn: esses hosts ja foram confirmados "up" no scan principal, entao pula a
        # descoberta de host de novo - evita falso negativo se o dispositivo bloquear ping.
        $saida = Invoke-NmapCapturado -NmapArgs (@('-Pn', '-p', '9100,631,515') + $ips)
        $saida | Out-File -FilePath $logPath -Encoding UTF8
    } catch {
        Write-Host "  Nao foi possivel confirmar impressoras: $($_.Exception.Message)" -ForegroundColor Yellow
        return $Linhas
    }

    # Quebra a saida do nmap por host (cada bloco comeca com "Nmap scan report for <ip>")
    $blocos = ($saida -join "`n") -split '(?=Nmap scan report for )'
    foreach ($bloco in $blocos) {
        if ($bloco -notmatch 'Nmap scan report for (\S+)') { continue }
        $ipBloco = $Matches[1]
        $temPortaAberta = $bloco -match '(?m)^(9100|631|515)/tcp\s+open'

        $linha = $Linhas | Where-Object { $_.IP -eq $ipBloco } | Select-Object -First 1
        if (-not $linha) { continue }

        if ($temPortaAberta) {
            $linha.TipoProvavel = "Impressora confirmada (porta de impressao aberta)"
        } else {
            $linha.TipoProvavel = "PC provavel (chip Realtek/generico, sem porta de impressao)"
        }
    }

    Write-Host "  Detalhes salvos em: $logPath" -ForegroundColor Cyan
    return $Linhas
}

function Resolve-NomeInterfaceNmap([string]$ipAlvo) {
    # O Nmap no Windows (via Npcap) NAO reconhece o nome amigavel do adaptador do Windows
    # (ex: "Ethernet") no parametro -e - ele usa nomes proprios tipo "eth0", "eth1". Essa
    # funcao acha o nome correto casando pelo IP, usando a saida de "nmap --iflist".
    try {
        $saida = Invoke-NmapCapturado -NmapArgs @('--iflist')
    } catch {
        return $null
    }

    foreach ($linha in $saida) {
        if ($linha -match '^(\S+)\s+\(\S+\)\s+(\d+\.\d+\.\d+\.\d+)/\d+\s') {
            if ($Matches[2] -eq $ipAlvo) { return $Matches[1] }
        }
    }
    return $null
}

function Find-DhcpNaoAutorizado([string]$nomeInterface, [string]$ip, [string]$pastaResultados, [string]$timestamp) {
    # Envia um DHCPDISCOVER de broadcast e escuta quem responde. Mais de um servidor
    # respondendo na mesma rede e um forte indicio de roteador/AP nao autorizado plugado
    # na rede (o cenario mais comum de "cabo clandestino" que tambem oferece IP por DHCP).
    Write-Host ""
    Write-Host "Verificando se ha mais de um servidor DHCP respondendo em '$nomeInterface' (indicio de equipamento nao autorizado)..." -ForegroundColor Cyan

    $devNmap = Resolve-NomeInterfaceNmap -ipAlvo $ip
    if (-not $devNmap) {
        Write-Host "  Nao foi possivel identificar o nome que o Nmap usa para '$nomeInterface' ($ip). Pulando essa checagem." -ForegroundColor Yellow
        return $null
    }

    $logPath = Join-Path $pastaResultados "dhcp_check_$($nomeInterface -replace '[^\w]', '_')_$timestamp.txt"
    try {
        # --script-timeout limita o tempo maximo dessa sondagem (evita ficar preso pra sempre
        # esperando resposta de broadcast que pode nunca chegar); a saida e mostrada ao vivo
        # no console (Tee-Object so espelha pro arquivo, nao suprime mais a tela). Usa
        # Invoke-NmapCapturado para nao deixar avisos do nmap em stderr (ex: "WARNING: No
        # targets were specified" - normal para um script de broadcast) virarem erro fatal.
        Invoke-NmapCapturado -NmapArgs @('--script', 'broadcast-dhcp-discover', '--script-timeout', '20s', '-e', $devNmap) | Tee-Object -FilePath $logPath
    } catch {
        Write-Host "  Nao foi possivel rodar a checagem de DHCP em '$nomeInterface': $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $logPath)) { return $null }
    $conteudo = Get-Content $logPath -Raw
    $qtdServidores = ([regex]::Matches($conteudo, 'Server Identifier:')).Count

    if ($qtdServidores -gt 1) {
        Write-Host "  ALERTA: $qtdServidores servidores DHCP diferentes responderam em '$nomeInterface'." -ForegroundColor Red
        Write-Host "  Isso pode indicar um roteador/switch/AP nao autorizado plugado na rede." -ForegroundColor Red
        Write-Host "  Detalhes salvos em: $logPath" -ForegroundColor Red
    } elseif ($qtdServidores -eq 1) {
        Write-Host "  OK: apenas 1 servidor DHCP respondeu em '$nomeInterface'." -ForegroundColor Green
    } else {
        Write-Host "  Nenhum servidor DHCP respondeu em '$nomeInterface' (rede pode usar IP fixo, ou o teste nao teve tempo de completar)." -ForegroundColor Yellow
    }

    return [PSCustomObject]@{
        Interface     = $nomeInterface
        QtdServidores = $qtdServidores
        LogPath       = $logPath
    }
}

function New-RelatorioResumo {
    param(
        [array]$Linhas,
        [array]$Faixas,
        [array]$AlertasDhcp,
        [string]$Timestamp,
        [string]$PastaResultados,
        [string]$TempoTotal = "",
        [string]$NumeroRegistro = "",
        [string]$Computador = ""
    )

    $linhasTexto = New-Object System.Collections.Generic.List[string]
    $add = { param($t) $linhasTexto.Add($t) }

    & $add "========================================================"
    & $add "  RESUMO DO SCAN DE REDE"
    & $add "========================================================"
    if ($NumeroRegistro) { & $add "Numero de registro: $NumeroRegistro" }
    if ($Computador) { & $add "Computador de origem: $Computador" }
    & $add "Data/Hora: $(Get-Date -Date ([datetime]::ParseExact($Timestamp,'yyyy-MM-dd_HHmmss',$null)) -Format 'dd/MM/yyyy HH:mm:ss')"
    if ($TempoTotal) { & $add "Tempo total da execucao (inicio ao fim): $TempoTotal" }
    & $add ""
    $Faixas = @($Faixas)
    $Linhas = @($Linhas)

    & $add "Redes escaneadas: $($Faixas.Count)"
    foreach ($faixa in $Faixas) {
        $qtd = @($Linhas | Where-Object { $_.Rede -eq $faixa }).Count
        & $add "  - $faixa  ->  $qtd dispositivo(s) ativo(s)"
    }
    & $add ""
    & $add "Total geral de dispositivos ativos encontrados: $($Linhas.Count)"
    & $add ""

    $equipamentos = @($Linhas | Where-Object { $_.PossivelEquipamentoRede -eq "SIM" })
    & $add "--------------------------------------------------------"
    & $add "Possiveis equipamentos de rede (roteador/switch/AP): $($equipamentos.Count)"
    & $add "--------------------------------------------------------"
    if ($equipamentos.Count -gt 0) {
        foreach ($eq in $equipamentos) {
            & $add "  - $($eq.IP)  [$($eq.MAC)]  $($eq.Fabricante)  -  $($eq.SO_Estimado)"
        }
    } else {
        & $add "  Nenhum encontrado."
    }
    & $add ""

    & $add "--------------------------------------------------------"
    & $add "Checagem de DHCP nao autorizado"
    & $add "--------------------------------------------------------"
    $AlertasDhcp = @($AlertasDhcp | Where-Object { $_ })
    if ($AlertasDhcp.Count -gt 0) {
        foreach ($alerta in $AlertasDhcp) {
            if (-not $alerta) { continue }
            if ($alerta.QtdServidores -gt 1) {
                & $add "  ALERTA em '$($alerta.Interface)': $($alerta.QtdServidores) servidores DHCP respondendo (ver $(Split-Path $alerta.LogPath -Leaf))"
            } elseif ($alerta.QtdServidores -eq 1) {
                & $add "  OK em '$($alerta.Interface)': 1 servidor DHCP (normal)"
            } else {
                & $add "  '$($alerta.Interface)': nenhum servidor DHCP respondeu (IP fixo, ou sem tempo de resposta)"
            }
        }
    } else {
        & $add "  Nao executada (faixa de rede foi forcada manualmente com -Rede)."
    }
    & $add ""

    $porFabricante = @($Linhas | Group-Object Fabricante | Sort-Object Count -Descending)
    & $add "--------------------------------------------------------"
    & $add "Dispositivos por fabricante"
    & $add "--------------------------------------------------------"
    foreach ($grupo in $porFabricante) {
        $nomeFab = if ($grupo.Name) { $grupo.Name } else { "(desconhecido)" }
        & $add "  $($grupo.Count)x  $nomeFab"
    }
    & $add ""

    & $add "--------------------------------------------------------"
    & $add "Sistemas operacionais estimados (top 10)"
    & $add "--------------------------------------------------------"
    $porSO = @($Linhas | Where-Object { $_.SO_Estimado } | Group-Object SO_Estimado | Sort-Object Count -Descending | Select-Object -First 10)
    if ($porSO.Count -gt 0) {
        foreach ($grupo in $porSO) {
            & $add "  $($grupo.Count)x  $($grupo.Name)"
        }
    } else {
        & $add "  Nenhum SO identificado com confianca."
    }
    & $add ""
    & $add "========================================================"

    $texto = $linhasTexto -join "`r`n"
    $resumoPath = Join-Path $PastaResultados "resumo_$Timestamp.txt"
    $texto | Out-File -FilePath $resumoPath -Encoding UTF8

    Write-Host ""
    Write-Host $texto -ForegroundColor Cyan

    return $resumoPath
}

function ConvertTo-TextoHtml([string]$texto) {
    if (-not $texto) { return "" }
    return $texto -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

function New-RelatorioHtml {
    param(
        [array]$Linhas,
        [array]$Faixas,
        [array]$AlertasDhcp,
        [string]$Timestamp,
        [string]$PastaResultados,
        [string]$TempoTotal = "",
        [string]$NumeroRegistro = "",
        [string]$Computador = ""
    )

    $Faixas = @($Faixas)
    $Linhas = @($Linhas)
    $AlertasDhcp = @($AlertasDhcp | Where-Object { $_ })
    $equipamentos = @($Linhas | Where-Object { $_.PossivelEquipamentoRede -eq "SIM" })
    $alertasDhcpCriticos = @($AlertasDhcp | Where-Object { $_.QtdServidores -gt 1 })
    $dataFormatada = Get-Date -Date ([datetime]::ParseExact($Timestamp, 'yyyy-MM-dd_HHmmss', $null)) -Format 'dd/MM/yyyy HH:mm:ss'

    $linhasPorRedeHtml = foreach ($faixa in $Faixas) {
        $qtd = @($Linhas | Where-Object { $_.Rede -eq $faixa }).Count
        "<tr><td class='mono'>$(ConvertTo-TextoHtml $faixa)</td><td>$qtd dispositivo(s)</td></tr>"
    }

    $linhasEquipHtml = if ($equipamentos.Count -gt 0) {
        foreach ($eq in $equipamentos) {
            "<tr><td class='mono destaque'>$(ConvertTo-TextoHtml $eq.IP)</td><td class='mono'>$(ConvertTo-TextoHtml $eq.MAC)</td><td>$(ConvertTo-TextoHtml $eq.Fabricante)</td><td>$(ConvertTo-TextoHtml $eq.SO_Estimado)</td><td class='mono'>$(ConvertTo-TextoHtml $eq.Rede)</td><td><span class='badge badge-alerta'>Verificar</span></td></tr>"
        }
    } else {
        "<tr><td colspan='6' class='sem-dados'>Nenhum equipamento de rede suspeito identificado.</td></tr>"
    }

    $linhasDhcpHtml = if ($AlertasDhcp.Count -gt 0) {
        foreach ($alerta in $AlertasDhcp) {
            if ($alerta.QtdServidores -gt 1) {
                $badge = "<span class='badge badge-alerta'>ALERTA - $($alerta.QtdServidores) servidores</span>"
            } elseif ($alerta.QtdServidores -eq 1) {
                $badge = "<span class='badge badge-ok'>OK - 1 servidor</span>"
            } else {
                $badge = "<span class='badge badge-neutro'>Sem resposta</span>"
            }
            "<tr><td>$(ConvertTo-TextoHtml $alerta.Interface)</td><td>$badge</td></tr>"
        }
    } else {
        "<tr><td colspan='2' class='sem-dados'>Checagem nao executada (faixa forcada manualmente com -Rede).</td></tr>"
    }

    $linhasInventarioHtml = foreach ($item in ($Linhas | Sort-Object Rede, { [version]($_.IP -replace '^\D+', '') } -ErrorAction SilentlyContinue)) {
        $marcador = if ($item.PossivelEquipamentoRede -eq "SIM") { "<span class='badge badge-alerta'>Equip. rede</span>" } else { "" }
        $ipClasse = if ($item.PossivelEquipamentoRede -eq "SIM") { "mono destaque" } else { "mono" }
        "<tr><td class='$ipClasse'>$(ConvertTo-TextoHtml $item.IP)</td><td>$(ConvertTo-TextoHtml $item.Hostname)</td><td class='mono'>$(ConvertTo-TextoHtml $item.MAC)</td><td>$(ConvertTo-TextoHtml $item.Fabricante) $marcador</td><td>$(ConvertTo-TextoHtml $item.TipoProvavel)</td><td>$(ConvertTo-TextoHtml $item.SO_Estimado)</td><td class='portas'>$(ConvertTo-TextoHtml $item.PortasAbertas)</td></tr>"
    }

    # Icones inline (SVG, sem dependencia externa) - estilo linha, 24x24, herdam a cor via currentColor
    $icoDispositivos = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>'
    $icoRede         = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15 15 0 0 1 0 20a15 15 0 0 1 0-20z"></path></svg>'
    $icoAlerta       = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
    $icoRoteador     = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="9" width="20" height="8" rx="2"></rect><line x1="6.5" y1="13" x2="6.51" y2="13"></line><line x1="9.5" y1="13" x2="9.51" y2="13"></line><path d="M12 9V5a2 2 0 0 1 2-2h1"></path></svg>'

    $html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatorio de Inventario de Rede - $dataFormatada</title>
<style>
  :root {
    --bg: #f1f5f9;
    --card: #ffffff;
    --texto: #0f172a;
    --texto-suave: #64748b;
    --borda: #e2e8f0;
    --azul: #2563eb;
    --azul-suave: #eff6ff;
    --verde: #16a34a;
    --verde-suave: #f0fdf4;
    --vermelho: #dc2626;
    --vermelho-suave: #fef2f2;
    --ambar: #d97706;
    --ambar-suave: #fffbeb;
  }
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, Roboto, Arial, sans-serif;
    background: var(--bg);
    color: var(--texto);
    margin: 0;
    padding: 0 0 48px 0;
  }
  .topo {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #1e3a5f 100%);
    color: #fff;
    padding: 40px 48px 32px;
  }
  .topo h1 { font-size: 26px; margin: 0 0 6px; font-weight: 700; letter-spacing: -.01em; }
  .topo .meta { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
  .pill {
    background: rgba(255,255,255,.12);
    border: 1px solid rgba(255,255,255,.18);
    color: #e2e8f0;
    padding: 5px 12px;
    border-radius: 999px;
    font-size: 12.5px;
  }
  .conteudo { max-width: 1180px; margin: -28px auto 0; padding: 0 32px; }

  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .kpi {
    background: var(--card);
    border-radius: 14px;
    padding: 20px 22px;
    box-shadow: 0 1px 3px rgba(0,0,0,.06), 0 8px 24px rgba(15,23,42,.06);
    border: 1px solid var(--borda);
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .kpi .icone {
    width: 44px; height: 44px; min-width: 44px;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    background: var(--azul-suave); color: var(--azul);
  }
  .kpi .icone svg { width: 22px; height: 22px; }
  .kpi.critico .icone { background: var(--vermelho-suave); color: var(--vermelho); }
  .kpi .numero { font-size: 30px; font-weight: 700; line-height: 1.1; }
  .kpi.critico .numero { color: var(--vermelho); }
  .kpi .rotulo { font-size: 12.5px; color: var(--texto-suave); margin-top: 2px; }

  .card {
    background: var(--card);
    border-radius: 14px;
    border: 1px solid var(--borda);
    box-shadow: 0 1px 3px rgba(0,0,0,.05);
    margin-bottom: 24px;
    overflow: hidden;
  }
  .card-titulo {
    display: flex; align-items: center; gap: 10px;
    padding: 16px 22px;
    border-bottom: 1px solid var(--borda);
    font-size: 15px; font-weight: 600;
  }
  .card-titulo svg { width: 18px; height: 18px; color: var(--azul); }
  .card-titulo.alerta svg { color: var(--vermelho); }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    text-align: left; padding: 10px 22px;
    background: #f8fafc; color: var(--texto-suave);
    font-size: 11.5px; text-transform: uppercase; letter-spacing: .05em; font-weight: 600;
    border-bottom: 1px solid var(--borda);
  }
  tbody td { padding: 10px 22px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: #fafbfc; }
  .mono { font-family: 'Cascadia Code', Consolas, 'Courier New', monospace; font-size: 12.5px; }
  .mono.destaque { color: var(--vermelho); font-weight: 700; }
  .portas { font-family: 'Cascadia Code', Consolas, 'Courier New', monospace; font-size: 11.5px; color: var(--texto-suave); }
  .sem-dados { color: #94a3b8; font-style: italic; text-align: center; padding: 18px !important; }

  .badge {
    display: inline-block; padding: 3px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 600; white-space: nowrap;
  }
  .badge-alerta { background: var(--vermelho-suave); color: var(--vermelho); }
  .badge-ok { background: var(--verde-suave); color: var(--verde); }
  .badge-neutro { background: #f1f5f9; color: var(--texto-suave); }

  .rodape {
    max-width: 1180px; margin: 8px auto 0; padding: 20px 32px 0;
    font-size: 11.5px; color: #94a3b8; line-height: 1.6;
    border-top: 1px solid var(--borda);
  }

  @media print {
    body { background: #fff; }
    .topo { background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .conteudo { margin-top: -20px; }
    .kpi, .card { box-shadow: none; break-inside: avoid; }
    table { font-size: 11px; }
  }
  @media (max-width: 640px) {
    .topo { padding: 28px 20px 24px; }
    .conteudo { padding: 0 14px; }
  }
</style>
</head>
<body>
  <div class="topo">
    <h1>Relatorio de Inventario de Rede Interna</h1>
    <div class="meta">
      $(if ($NumeroRegistro) { "<span class='pill'>Registro N&#186; $(ConvertTo-TextoHtml $NumeroRegistro)</span>" })
      $(if ($Computador) { "<span class='pill'>Computador: $(ConvertTo-TextoHtml $Computador)</span>" })
      <span class="pill">Gerado em $dataFormatada</span>
      <span class="pill">$($Faixas.Count) rede(s) escaneada(s)</span>
      <span class="pill">$($Faixas -join ', ')</span>
      $(if ($TempoTotal) { "<span class='pill'>Duracao total: $TempoTotal</span>" })
    </div>
  </div>

  <div class="conteudo">
    <div class="kpis">
      <div class="kpi">
        <div class="icone">$icoDispositivos</div>
        <div><div class="numero">$($Linhas.Count)</div><div class="rotulo">Dispositivos ativos</div></div>
      </div>
      <div class="kpi">
        <div class="icone">$icoRede</div>
        <div><div class="numero">$($Faixas.Count)</div><div class="rotulo">Redes / segmentos</div></div>
      </div>
      <div class="kpi $(if ($equipamentos.Count -gt 0) { 'critico' })">
        <div class="icone">$icoRoteador</div>
        <div><div class="numero">$($equipamentos.Count)</div><div class="rotulo">Possivel equip. nao mapeado</div></div>
      </div>
      <div class="kpi $(if ($alertasDhcpCriticos.Count -gt 0) { 'critico' })">
        <div class="icone">$icoAlerta</div>
        <div><div class="numero">$($alertasDhcpCriticos.Count)</div><div class="rotulo">Alertas de DHCP duplicado</div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-titulo">$icoRede Dispositivos por rede / segmento</div>
      <table>
        <thead><tr><th>Rede (CIDR)</th><th>Dispositivos ativos</th></tr></thead>
        <tbody>$($linhasPorRedeHtml -join "`n")</tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-titulo alerta">$icoAlerta Pontos de atencao — possivel equipamento de rede nao mapeado</div>
      <table>
        <thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>SO estimado</th><th>Rede</th><th></th></tr></thead>
        <tbody>$($linhasEquipHtml -join "`n")</tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-titulo">$icoAlerta Checagem de DHCP nao autorizado</div>
      <table>
        <thead><tr><th>Interface</th><th>Resultado</th></tr></thead>
        <tbody>$($linhasDhcpHtml -join "`n")</tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-titulo">$icoDispositivos Inventario completo</div>
      <table>
        <thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Fabricante</th><th>Tipo provavel</th><th>SO estimado</th><th>Portas abertas</th></tr></thead>
        <tbody>$($linhasInventarioHtml -join "`n")</tbody>
      </table>
    </div>

    <div class="rodape">
      Relatorio gerado automaticamente por scan-rede.ps1 (Nmap). Cobre apenas os segmentos de rede aos quais o computador de origem do scan estava conectado no momento da execucao; redes fisicamente isoladas (sem rota ate este ponto) nao aparecem neste levantamento.
    </div>
  </div>
</body>
</html>
"@

    $htmlPath = Join-Path $PastaResultados "relatorio_$Timestamp.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    return $htmlPath
}

function Format-Decorrido([TimeSpan]$tempo) {
    if ($tempo.TotalHours -ge 1) {
        return "{0:00}:{1:00}:{2:00}" -f [int]$tempo.TotalHours, $tempo.Minutes, $tempo.Seconds
    }
    return "{0:00}:{1:00}" -f $tempo.Minutes, $tempo.Seconds
}

# Sequencias ANSI para a barra de progresso moderna. O console do Windows 10/11
# (build >= 10586) processa VT nativamente, mas so quando o modo e habilitado
# explicitamente no handle de saida - por isso a chamada abaixo via P/Invoke.
# Se falhar (ex: saida redirecionada para arquivo), o script cai de volta para
# texto puro sem cor, sem quebrar nada.
$script:corSuportada = $false
function Enable-AnsiConsole {
    try {
        $definicao = @'
using System;
using System.Runtime.InteropServices;
public static class VtConsole {
    [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int h);
    [DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr hConsole, out uint mode);
    [DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr hConsole, uint mode);
}
'@
        if (-not ("VtConsole" -as [type])) {
            Add-Type -TypeDefinition $definicao -ErrorAction Stop
        }
        $handle = [VtConsole]::GetStdHandle(-11)
        $modo = 0
        if ([VtConsole]::GetConsoleMode($handle, [ref]$modo)) {
            [VtConsole]::SetConsoleMode($handle, $modo -bor 0x0004) | Out-Null
            $script:corSuportada = $true
        }
    } catch {
        $script:corSuportada = $false
    }
}
Enable-AnsiConsole

$script:ansiEsc      = [char]27
$script:ansiReset    = "$($script:ansiEsc)[0m"
$script:ansiCiano    = "$($script:ansiEsc)[1;96m"
$script:ansiAmarelo  = "$($script:ansiEsc)[93m"
$script:ansiVerde    = "$($script:ansiEsc)[1;92m"
$script:ansiVermelho = "$($script:ansiEsc)[1;91m"
$script:ansiRoxo     = "$($script:ansiEsc)[1;95m"
$script:ansiAzul     = "$($script:ansiEsc)[1;94m"
$script:ansiLaranja  = "$($script:ansiEsc)[38;5;208m"
$script:ansiCinza    = "$($script:ansiEsc)[90m"
$script:ansiBranco   = "$($script:ansiEsc)[1;97m"
$script:spinnerFrames = @('|', '/', '-', '\')
# Uma cor por rede (cicla se houver mais redes que cores), so pra dar pra acompanhar
# visualmente qual linha do log pertence a qual faixa no meio de varias rodando juntas.
$script:paletaCoresRede = @($script:ansiCiano, $script:ansiRoxo, $script:ansiAmarelo, $script:ansiAzul)

function Format-TextoTruncado([string]$Texto, [int]$Largura) {
    # Corta o texto na largura da coluna antes de alinhar - sem isso, um valor mais
    # comprido que a coluna (ex: nome de fase longo do nmap) estoura pro lado e
    # desalinha todas as colunas seguintes daquela linha.
    if ($Texto.Length -gt $Largura) { return $Texto.Substring(0, $Largura) }
    return $Texto
}

function Format-TextoCentralizado([string]$Texto, [int]$Largura) {
    $Texto = Format-TextoTruncado $Texto $Largura
    $espaco = $Largura - $Texto.Length
    $esquerda = [int][Math]::Floor($espaco / 2)
    $direita = $espaco - $esquerda
    return (' ' * $esquerda) + $Texto + (' ' * $direita)
}

# Larguras das colunas da tabela de log, na ordem hora/rede/fase/%/eta/status. Um so
# lugar pra manter as bordas (Format-BordaTabela) e as celulas (Format-LinhaTabelaLog)
# sempre alinhadas entre si.
$script:larguraColunasLog = @(8, 23, 19, 7, 10, 24)

function Format-BordaTabela([string]$Tipo) {
    switch ($Tipo) {
        'Topo' { $esq = [char]0x250C; $meio = [char]0x252C; $dir = [char]0x2510 }
        'Meio' { $esq = [char]0x251C; $meio = [char]0x253C; $dir = [char]0x2524 }
        'Base' { $esq = [char]0x2514; $meio = [char]0x2534; $dir = [char]0x2518 }
    }
    $traco = [char]0x2500
    $segmentos = $script:larguraColunasLog | ForEach-Object { [string]$traco * ($_ + 2) }
    $linha = "  " + $esq + ($segmentos -join $meio) + $dir
    if ($script:corSuportada) { return "$($script:ansiCinza)$linha$($script:ansiReset)" }
    return $linha
}

function Format-LinhaTabelaLog {
    param(
        [string]$Hora,
        [string]$Rede,
        [string]$CorRede,
        [string]$Fase,
        [string]$Percentual = "",
        [string]$Eta = "",
        [string]$Status,
        [string]$CorStatus,
        [switch]$Cabecalho
    )

    $w = $script:larguraColunasLog

    if ($Cabecalho) {
        # So o cabecalho fica centralizado nas colunas - as linhas de dados usam o
        # alinhamento normal (esquerda/direita), que fica mais facil de ler em log.
        $horaF   = Format-TextoCentralizado $Hora $w[0]
        $redeF   = Format-TextoCentralizado $Rede $w[1]
        $faseF   = Format-TextoCentralizado $Fase $w[2]
        $pctF    = Format-TextoCentralizado $Percentual $w[3]
        $etaF    = Format-TextoCentralizado $Eta $w[4]
        $statusF = Format-TextoCentralizado $Status $w[5]
    } else {
        # Hora, rede, % e ETA ficam centralizadas tambem nas linhas de dados (nao so
        # no cabecalho); fase/status continuam alinhadas a esquerda, que fica mais
        # facil de ler textos mais longos e variados.
        $horaF   = Format-TextoCentralizado $Hora $w[0]
        $redeF   = Format-TextoCentralizado $Rede $w[1]
        # O traco "-" (placeholder de fase ainda nao definida) fica centralizado pra
        # ficar padronizado visualmente; valores reais continuam alinhados a esquerda.
        $faseF   = if ($Fase -eq "-") { Format-TextoCentralizado $Fase $w[2] } else { (Format-TextoTruncado $Fase $w[2]).PadRight($w[2]) }
        $pctF    = Format-TextoCentralizado $Percentual $w[3]
        $etaF    = Format-TextoCentralizado $Eta $w[4]
        $statusF = (Format-TextoTruncado $Status $w[5]).PadRight($w[5])
    }

    $pipe = [char]0x2502
    if (-not $script:corSuportada) {
        return "  $pipe $horaF $pipe $redeF $pipe $faseF $pipe $pctF $pipe $etaF $pipe $statusF $pipe"
    }

    $p = "$($script:ansiCinza)$pipe$($script:ansiReset)"
    return "  $p $($script:ansiCinza)$horaF$($script:ansiReset) $p $CorRede$redeF$($script:ansiReset) $p $($script:ansiBranco)$faseF$($script:ansiReset) $p $($script:ansiBranco)$pctF$($script:ansiReset) $p $($script:ansiCinza)$etaF$($script:ansiReset) $p $CorStatus$statusF$($script:ansiReset) $p"
}

function Write-LinhaLogParalelo {
    # Escreve uma linha do log. Se $LinhaExistente for informado (linha "viva" de uma
    # fase ainda em andamento), reescreve por cima daquela linha em vez de criar uma
    # nova - da a impressao de uma unica linha atualizando em tempo real. So cria
    # linha nova quando $LinhaExistente e $null (primeira leitura de uma fase, ou
    # console sem suporte a ANSI, onde reposicionar cursor nao e confiavel).
    param(
        [string]$Texto,
        [Nullable[int]]$LinhaExistente = $null
    )

    if (-not $script:corSuportada) {
        Write-Host $Texto
        return $null
    }

    if ($null -ne $LinhaExistente) {
        try {
            $linhaFinal = [Console]::CursorTop
            [Console]::SetCursorPosition(0, $LinhaExistente)
            Write-Host -NoNewline "$($script:ansiEsc)[2K$Texto"
            [Console]::SetCursorPosition(0, $linhaFinal)
            return $LinhaExistente
        } catch {
            # Buffer do console menor que o esperado ou posicao invalida - segue
            # criando uma linha nova, sem travar a execucao por causa disso.
        }
    }

    $linha = [Console]::CursorTop
    Write-Host $Texto
    return $linha
}

function Invoke-NmapsComLogParalelo {
    param(
        [string[]]$Faixas,
        [string]$PastaResultados,
        [string]$Timestamp
    )
    # Roda um nmap por faixa de rede simultaneamente (Start-Process nao bloqueia) e
    # registra o progresso como um LOG de tabela. Enquanto uma fase esta em andamento,
    # a linha dela e reescrita no lugar (%/ETA atualizando em tempo real); quando a
    # fase muda ou a rede termina, aquela linha fica congelada com o resultado final e
    # uma linha nova e permanente comeca para a proxima fase - continua dando pra
    # rolar pra tras e ver o historico completo de cada etapa que ja fechou.
    $tarefas = foreach ($i in 0..($Faixas.Count - 1)) {
        $faixa = $Faixas[$i]
        $faixaSlug = ($faixa -replace '[/:]', '_')
        $xmlPath = Join-Path $PastaResultados "scan_${faixaSlug}_$Timestamp.xml"
        $outPath = Join-Path $PastaResultados "scan_${faixaSlug}_$Timestamp.progresso.log"
        $errPath = Join-Path $PastaResultados "scan_${faixaSlug}_$Timestamp.progresso.err.log"
        $nmapArgs = @('-O', '-sV', '--osscan-guess', '--stats-every', '3s', '-oX', $xmlPath, $faixa)
        $argsQuoted = $nmapArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }

        $processo = Start-Process -FilePath $script:nmapExe -ArgumentList $argsQuoted `
            -RedirectStandardOutput $outPath -RedirectStandardError $errPath -PassThru -NoNewWindow

        [PSCustomObject]@{
            Faixa               = $faixa
            Cor                 = $script:paletaCoresRede[$i % $script:paletaCoresRede.Count]
            XmlPath             = $xmlPath
            OutPath             = $outPath
            ErrPath             = $errPath
            Processo            = $processo
            Cronometro          = [Diagnostics.Stopwatch]::StartNew()
            Concluido           = $false
            FaseLogada          = ""
            PercentualLogado    = -1.0
            EtaLogado           = "-"
            LinhaViva           = $null
        }
    }

    $cronometroGeral = [Diagnostics.Stopwatch]::StartNew()
    # Alem da fase, tambem captura o ETC (tempo restante estimado) que o proprio nmap
    # recalcula a cada atualizacao, para exibir um ETA por rede.
    $regexFase = '^(.+?)\s+Timing:\s+About\s+(\d+(?:\.\d+)?)%\s+done(?:;\s*ETC:\s*\S+\s*\(([^)]+)\s*remaining\))?'

    Write-Host ""
    Write-Host (Format-BordaTabela -Tipo Topo)
    Write-Host (Format-LinhaTabelaLog -Hora "hora" -Rede "rede" -CorRede $script:ansiCinza -Fase "fase" -Percentual "%" -Eta "eta" -Status "status" -CorStatus $script:ansiCinza -Cabecalho)
    Write-Host (Format-BordaTabela -Tipo Meio)
    foreach ($t in $tarefas) {
        $linha = Format-LinhaTabelaLog -Hora (Format-Decorrido $cronometroGeral.Elapsed) -Rede $t.Faixa -CorRede $t.Cor -Fase "-" -Percentual "0.0%" -Eta "-" -Status "iniciado" -CorStatus $script:ansiCiano
        $t.LinhaViva = Write-LinhaLogParalelo -Texto $linha
    }

    while ($tarefas | Where-Object { -not $_.Concluido }) {
        Start-Sleep -Milliseconds 300
        foreach ($t in $tarefas) {
            if ($t.Concluido) { continue }

            if ($t.Processo.HasExited) {
                $t.Concluido = $true
                $t.Cronometro.Stop()
                $ok = ($t.Processo.ExitCode -eq 0)
                $status = if ($ok) { "concluido em $(Format-Decorrido $t.Cronometro.Elapsed)" } else { "erro (codigo $($t.Processo.ExitCode))" }
                $corStatus = if ($ok) { $script:ansiVerde } else { $script:ansiVermelho }
                $linha = Format-LinhaTabelaLog -Hora (Format-Decorrido $cronometroGeral.Elapsed) -Rede $t.Faixa -CorRede $t.Cor -Fase "-" -Percentual "100.0%" -Eta "-" -Status $status -CorStatus $corStatus
                # Congela a linha da ultima fase em andamento virando a linha final,
                # em vez de abrir mais uma linha nova so pra dizer "concluido".
                Write-LinhaLogParalelo -Texto $linha -LinhaExistente $t.LinhaViva | Out-Null
                continue
            }

            $linhaJaAtualizada = $false

            if (Test-Path $t.OutPath) {
                $linhaFase = Get-Content $t.OutPath -Tail 20 -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match $regexFase } | Select-Object -Last 1
                if ($linhaFase -and $linhaFase -match $regexFase) {
                    $fase = $Matches[1]
                    $percentual = [double]$Matches[2]
                    $eta = if ($Matches[3]) { $Matches[3] } else { "calculando" }

                    if ($fase -ne $t.FaseLogada) {
                        # Fase nova: congela a linha da fase anterior (se existia) como
                        # concluida, e abre uma linha nova e propria para a fase atual.
                        if ($t.FaseLogada -and $null -ne $t.LinhaViva) {
                            $linhaAntiga = Format-LinhaTabelaLog -Hora (Format-Decorrido $cronometroGeral.Elapsed) -Rede $t.Faixa -CorRede $t.Cor -Fase $t.FaseLogada -Percentual "100.0%" -Eta "-" -Status "concluido" -CorStatus $script:ansiVerde
                            Write-LinhaLogParalelo -Texto $linhaAntiga -LinhaExistente $t.LinhaViva | Out-Null
                        }

                        $t.FaseLogada = $fase
                        $t.PercentualLogado = $percentual
                        $t.EtaLogado = $eta
                        $linhaNova = Format-LinhaTabelaLog -Hora (Format-Decorrido $cronometroGeral.Elapsed) -Rede $t.Faixa -CorRede $t.Cor -Fase $fase -Percentual ("{0:0.0}%" -f $percentual) -Eta $eta -Status "iniciado" -CorStatus $script:ansiCiano
                        $t.LinhaViva = Write-LinhaLogParalelo -Texto $linhaNova
                        $linhaJaAtualizada = $true
                    } else {
                        $t.PercentualLogado = $percentual
                        $t.EtaLogado = $eta
                    }
                }
            }

            # Batimento: mesmo sem leitura nova do nmap (que so atualiza a cada ~3s),
            # reescreve a linha viva a cada volta do loop (~300ms) so pra manter a
            # coluna "hora" andando feito um cronometro de verdade, em vez de travada
            # esperando a proxima leitura de percentual.
            if (-not $linhaJaAtualizada -and $t.FaseLogada -and $null -ne $t.LinhaViva) {
                $linha = Format-LinhaTabelaLog -Hora (Format-Decorrido $cronometroGeral.Elapsed) -Rede $t.Faixa -CorRede $t.Cor -Fase $t.FaseLogada -Percentual ("{0:0.0}%" -f $t.PercentualLogado) -Eta $t.EtaLogado -Status "em andamento" -CorStatus $script:ansiAmarelo
                $t.LinhaViva = Write-LinhaLogParalelo -Texto $linha -LinhaExistente $t.LinhaViva
            } elseif (-not $linhaJaAtualizada -and -not $t.FaseLogada -and $null -ne $t.LinhaViva) {
                # Ainda na fase "-" inicial (nenhuma fase do nmap detectada ainda).
                $linha = Format-LinhaTabelaLog -Hora (Format-Decorrido $cronometroGeral.Elapsed) -Rede $t.Faixa -CorRede $t.Cor -Fase "-" -Percentual "0.0%" -Eta "-" -Status "iniciado" -CorStatus $script:ansiCiano
                $t.LinhaViva = Write-LinhaLogParalelo -Texto $linha -LinhaExistente $t.LinhaViva
            }
        }
    }

    Write-Host (Format-BordaTabela -Tipo Base)

    foreach ($t in $tarefas) {
        if ($t.Processo.ExitCode -ne 0) {
            $erroTexto = if (Test-Path $t.ErrPath) { (Get-Content $t.ErrPath -Raw) } else { "" }
            Write-Host "  Aviso: nmap para $($t.Faixa) terminou com codigo $($t.Processo.ExitCode). $erroTexto" -ForegroundColor Yellow
        }
        Remove-Item $t.OutPath, $t.ErrPath -Force -ErrorAction SilentlyContinue
    }

    return $tarefas
}

function ConvertTo-CIDR([string]$ip, [int]$prefixLength) {
    $ipBytes = ([Net.IPAddress]$ip).GetAddressBytes()
    # bitwise AND com a mascara derivada do prefixo, para achar o endereco de rede
    $maskBits = ('1' * $prefixLength).PadRight(32, '0')
    $maskBytes = for ($i = 0; $i -lt 32; $i += 8) {
        [Convert]::ToByte($maskBits.Substring($i, 8), 2)
    }
    $redeBytes = for ($i = 0; $i -lt 4; $i++) { $ipBytes[$i] -band $maskBytes[$i] }
    $redeIp = ($redeBytes -join '.')
    return "$redeIp/$prefixLength"
}

function Wait-RedesLocaisAtivas {
    # Espera ate a rede ficar disponivel de verdade, tentando por ate ~30 segundos.
    # Importante quando o cabo acabou de ser plugado: o Windows leva alguns segundos
    # para negociar o IP via DHCP, entao a primeira tentativa pode nao achar nada ainda.
    $tentativas = 10
    $intervaloSegundos = 3

    for ($i = 1; $i -le $tentativas; $i++) {
        $redes = Get-RedesLocaisAtivas
        if ($redes -and @($redes).Count -gt 0) {
            if ($i -gt 1) { Write-Host "" }
            return $redes
        }

        if ($i -eq 1) {
            Write-Host "Aguardando o Windows obter IP via DHCP no cabo/Wi-Fi conectado..." -ForegroundColor Yellow -NoNewline
        } else {
            Write-Host "." -ForegroundColor Yellow -NoNewline
        }
        Start-Sleep -Seconds $intervaloSegundos
    }

    Write-Host ""
    return $null
}

function Get-RedesLocaisAtivas {
    # Usa a API .NET diretamente (System.Net.NetworkInformation) em vez de Get-NetIPConfiguration,
    # que depende do WMI/CIM e pode falhar com "Classe invalida" em maquinas com o repositorio
    # WMI corrompido (comum em PCs corporativos antigos ou com muitos softwares de gestao instalados).
    $palavrasVirtuais = @('vEthernet', 'Loopback', 'Virtual', 'WSL', 'Hyper-V', 'TAP', 'Npcap', 'VMware', 'VirtualBox')

    $interfaces = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.OperationalStatus -eq 'Up' -and
        $_.NetworkInterfaceType -ne [Net.NetworkInformation.NetworkInterfaceType]::Loopback -and
        $_.NetworkInterfaceType -ne [Net.NetworkInformation.NetworkInterfaceType]::Tunnel
    }

    $redes = foreach ($nic in $interfaces) {
        $nome = $nic.Name
        $descricao = $nic.Description

        $ehVirtual = $false
        foreach ($palavra in $palavrasVirtuais) {
            if ($nome -match $palavra -or $descricao -match $palavra) { $ehVirtual = $true; break }
        }
        if ($ehVirtual) { continue }

        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
            $ip = $ua.Address.ToString()
            if ($ip -like "169.254.*") { continue }  # APIPA, sem rede real
            if (-not $ua.PrefixLength) { continue }

            $cidr = ConvertTo-CIDR -ip $ip -prefixLength $ua.PrefixLength
            [PSCustomObject]@{
                Adaptador = $nome
                IP        = $ip
                CIDR      = $cidr
            }
        }
    }
    return $redes
}

# ============================== EXECUCAO ==============================
$cronometroTotal = [Diagnostics.Stopwatch]::StartNew()
try {
    $ErrorActionPreference = "Stop"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.ServicePointManager]::SecurityProtocol

    # --- Autoeleva o script (necessario para instalar o Nmap/Npcap e para o -O do scan) ---
    if (-not (Test-Administrador)) {
        Write-Host "Solicitando elevacao de administrador (aceite o prompt do Windows)..." -ForegroundColor Yellow
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        if ($Rede) { $argList += @('-Rede', "`"$($Rede -join ',')`"") }
        if ($Forcar) { $argList += '-Forcar' }

        try {
            Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop
        } catch {
            throw "Nao foi possivel elevar para Administrador (voce recusou o prompt do UAC, ou nao tem permissao de admin nesta conta). Detalhe: $($_.Exception.Message)"
        }
        exit
    }

    # Ajusta a codepage do console para UTF-8 (65001). Sem isso, o console do Windows
    # continua interpretando a saida com a codepage antiga (ex: 850/1252) mesmo que o
    # .NET mande bytes UTF-8, e os caracteres de bloco/spinner da barra de progresso
    # aparecem como retangulos vazios ("tofu") em vez do simbolo correto.
    try {
        chcp.com 65001 | Out-Null
        [Console]::OutputEncoding = [Text.Encoding]::UTF8
    } catch {
        # Se falhar (ex: console nao suporta), a barra de progresso cai para o modo
        # texto simples automaticamente via $script:corSuportada.
    }

    # --- Localiza o nmap: PATH -> pasta "nmap" ao lado do script (pen drive) -> instala automaticamente ---
    $nmapCmd = Get-Command nmap -ErrorAction SilentlyContinue
    $nmapExe = $null
    if ($nmapCmd) {
        $nmapExe = $nmapCmd.Source
    } else {
        $nmapLocal = Join-Path $PSScriptRoot "nmap\nmap.exe"
        if (Test-Path $nmapLocal) { $nmapExe = $nmapLocal }
    }

    if (-not $nmapExe) {
        $nmapExe = Install-Nmap
    }
    $script:nmapExe = $nmapExe

    $pastaResultados = Join-Path $PSScriptRoot "resultados"
    if (-not (Test-Path $pastaResultados)) {
        New-Item -ItemType Directory -Path $pastaResultados | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $numeroRegistro = Get-ProximoNumeroRegistro
    $nomeComputador = Get-NomeComputadorCompleto
    Write-Host "Registro N. $numeroRegistro  -  Computador: $nomeComputador" -ForegroundColor Cyan

    # --- Determina a(s) faixa(s) a escanear ---
    $faixas = @()
    if ($Rede) {
        $faixas = @($Rede)
        Write-Host "Usando faixa(s) forcada(s): $($Rede -join ', ')" -ForegroundColor Cyan
    } else {
        $redesDetectadas = Wait-RedesLocaisAtivas
        if (-not $redesDetectadas -or @($redesDetectadas).Count -eq 0) {
            throw "Nao foi possivel detectar nenhuma rede local ativa apos ~30s de espera. Confira se o cabo esta bem conectado (LED de link aceso) e se a porta do switch esta ativa, ou informe a faixa manualmente: .\scan-rede.ps1 -Rede 10.5.20.0/24"
        }

        Write-Host "Rede(s) detectada(s):" -ForegroundColor Cyan
        $redesDetectadas | ForEach-Object { Write-Host "  - $($_.Adaptador): $($_.IP) -> $($_.CIDR)" -ForegroundColor White }

        $faixas = @($redesDetectadas.CIDR | Select-Object -Unique)

        # --- Pre-teste: compara com redes ja conhecidas (escaneadas em execucoes anteriores) ---
        $redesConhecidas = Get-RedesConhecidas
        $faixasConhecidas = @($faixas | Where-Object { $atual = $_; $redesConhecidas | Where-Object { $_.CIDR -eq $atual } })
        $faixasNovas = @($faixas | Where-Object { $atual = $_; -not ($redesConhecidas | Where-Object { $_.CIDR -eq $atual }) })

        if ($faixasConhecidas.Count -gt 0) {
            Write-Host ""
            Write-Host "Rede(s) ja conhecida(s) (escaneada(s) antes):" -ForegroundColor Yellow
            foreach ($fc in $faixasConhecidas) {
                $info = $redesConhecidas | Where-Object { $_.CIDR -eq $fc } | Select-Object -First 1
                Write-Host "  - $fc  (1a vez: $($info.PrimeiraVez), ultima vez: $($info.UltimaVez), $($info.QtdExecucoes)x escaneada)" -ForegroundColor Yellow
            }
        }

        if (-not $Forcar -and $faixasNovas.Count -eq 0) {
            Write-Host ""
            Write-Host "Nenhuma rede NOVA detectada neste ponto — esse cabo/ponto leva a uma rede ja mapeada." -ForegroundColor Green
            Write-Host "Scan completo pulado automaticamente (use -Forcar para escanear mesmo assim)." -ForegroundColor Green
            Aguardar-Saida
            exit 0
        }

        if ($Forcar) {
            Write-Host ""
            Write-Host "-Forcar ativo: escaneando todas as redes detectadas, mesmo as ja conhecidas." -ForegroundColor Yellow
        } elseif ($faixasConhecidas.Count -gt 0) {
            Write-Host ""
            Write-Host "Rede(s) NOVA(s) detectada(s) — prosseguindo so com elas (as ja conhecidas acima foram puladas):" -ForegroundColor Green
            $faixasNovas | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            $faixas = $faixasNovas
        }

        # Checagem de DHCP nao autorizado, uma vez por adaptador fisico detectado
        $adaptadoresUnicos = $redesDetectadas | Group-Object Adaptador | ForEach-Object { $_.Group | Select-Object -First 1 }
        $alertasDhcp = $adaptadoresUnicos | ForEach-Object {
            Find-DhcpNaoAutorizado -nomeInterface $_.Adaptador -ip $_.IP -pastaResultados $pastaResultados -timestamp $timestamp
        }
    }

    $linhasTotais = @()

    Write-Host ""
    if ($faixas.Count -gt 1) {
        Write-Host "Escaneando $($faixas.Count) redes em paralelo ... isso pode levar alguns minutos." -ForegroundColor Cyan
    } else {
        Write-Host "Escaneando $($faixas[0]) ... isso pode levar alguns minutos." -ForegroundColor Cyan
    }

    # Dispara um nmap por faixa ao mesmo tempo (em vez de rede por rede em sequencia) e
    # desenha um painel com uma linha de progresso por rede, cada uma virando verde
    # assim que aquela faixa termina - as demais continuam rodando normalmente.
    $tarefasScan = Invoke-NmapsComLogParalelo -Faixas $faixas -PastaResultados $pastaResultados -Timestamp $timestamp

    foreach ($tarefa in $tarefasScan) {
        $faixa = $tarefa.Faixa
        $xmlPath = $tarefa.XmlPath

        if (-not (Test-Path $xmlPath)) {
            Write-Host "O Nmap nao gerou saida para $faixa. Pulando." -ForegroundColor Red
            continue
        }

        # So marca a rede como "conhecida" depois do scan completar de verdade (nao no modo -Rede forcado manualmente)
        if (-not $Rede) {
            Save-RedeConhecida -cidr $faixa -timestamp $timestamp
        }

        [xml]$scanXml = Get-Content $xmlPath

        foreach ($host_ in $scanXml.nmaprun.host) {
            if ($host_.status.state -ne "up") { continue }

            $ip = ($host_.address | Where-Object { $_.addrtype -eq "ipv4" }).addr
            $macNode = $host_.address | Where-Object { $_.addrtype -eq "mac" }
            $mac = $macNode.addr
            $fabricante = $macNode.vendor
            $hostname = ($host_.hostnames.hostname | Select-Object -First 1).name

            $portasAbertas = @()
            if ($host_.ports.port) {
                foreach ($p in $host_.ports.port) {
                    if ($p.state.state -eq "open") {
                        $servico = $p.service.name
                        $versaoServico = "$($p.service.product) $($p.service.version)".Trim()
                        $portasAbertas += "$($p.portid)/$($p.protocol)($servico $versaoServico)".Trim()
                    }
                }
            }

            $so = ($host_.os.osmatch | Select-Object -First 1).name
            $possivelEquipRede = if (Test-EquipamentoDeRede $fabricante) { "SIM" } else { "" }
            $tipoProvavel = Get-TipoProvavel -fabricante $fabricante -mac $mac -soEstimado $so

            $linhasTotais += [PSCustomObject]@{
                Rede                    = $faixa
                IP                      = $ip
                Hostname                = $hostname
                MAC                     = $mac
                Fabricante              = $fabricante
                PossivelEquipamentoRede = $possivelEquipRede
                TipoProvavel            = $tipoProvavel
                SO_Estimado             = $so
                PortasAbertas           = ($portasAbertas -join "; ")
                DataScan                = $timestamp
                NumeroRegistro          = $numeroRegistro
                ComputadorOrigem        = $nomeComputador
            }
        }
    }

    $linhasTotais = Confirm-Impressoras -Linhas $linhasTotais -PastaResultados $pastaResultados -Timestamp $timestamp

    $csvPath = Join-Path $pastaResultados "inventario_$timestamp.csv"
    $linhasTotais | Sort-Object Rede, { [version]($_.IP -replace '^\D+', '') } -ErrorAction SilentlyContinue | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $cronometroTotal.Stop()
    $tempoTotalTexto = Format-Decorrido $cronometroTotal.Elapsed

    $resumoPath = New-RelatorioResumo -Linhas $linhasTotais -Faixas $faixas -AlertasDhcp $alertasDhcp -Timestamp $timestamp -PastaResultados $pastaResultados -TempoTotal $tempoTotalTexto -NumeroRegistro $numeroRegistro -Computador $nomeComputador
    $htmlPath = New-RelatorioHtml -Linhas $linhasTotais -Faixas $faixas -AlertasDhcp $alertasDhcp -Timestamp $timestamp -PastaResultados $pastaResultados -TempoTotal $tempoTotalTexto -NumeroRegistro $numeroRegistro -Computador $nomeComputador

    Write-Host ""
    Write-Host "Concluido em $tempoTotalTexto! $($linhasTotais.Count) dispositivos ativos encontrados no total." -ForegroundColor Green
    Write-Host "CSV salvo em: $csvPath" -ForegroundColor Green
    Write-Host "Resumo salvo em: $resumoPath" -ForegroundColor Green
    Write-Host "Relatorio para apresentacao (HTML) salvo em: $htmlPath" -ForegroundColor Green

    Aguardar-Saida
} catch {
    $cronometroTotal.Stop()
    Write-Host ""
    Write-Host "ERRO apos $(Format-Decorrido $cronometroTotal.Elapsed) de execucao: $($_.Exception.Message)" -ForegroundColor Red
    Aguardar-Saida
    exit 1
}
