# Checklist Técnico Completo — scan-rede.ps1

> **Criado por: Matheus Coelho**
> Este projeto (script + documentação) é de autoria de Matheus Coelho. Ao copiar, adaptar ou redistribuir este material, mantenha esta atribuição.

Documento de referência exaustivo: tudo que o script usa, tudo que ele faz, e como ele faz. Complementa o [LEIA-ME.md](LEIA-ME.md) (mais narrativo) com uma visão em checklist, pensada para consulta rápida e auditoria.

---

## 1. Requisitos e dependências

- [ ] **Sistema operacional:** Windows (usa APIs .NET/Win32 específicas do Windows — não roda em Linux/Mac)
- [ ] **PowerShell:** Windows PowerShell 5.1 (built-in em qualquer Windows 10/11) — não precisa do PowerShell 7/Core
- [ ] **Privilégios de administrador local** — o script se autoeleva sozinho (dispara UAC), mas a conta precisa ter direito de virar admin
- [ ] **Nmap 7.x + Npcap** — instalado automaticamente pelo script se não existir (sempre a versão mais recente disponível em `nmap.org`, com checagem semanal de atualização); pode também ser pré-instalado ou colocado manualmente na pasta `nmap\`
- [ ] **Conexão com a internet** — necessária para instalar o Nmap na primeira vez, e recomendável periodicamente para a checagem semanal de atualização (falha na checagem não bloqueia a execução — o script segue com a versão já instalada)
- [ ] **Espaço em disco livre** — ideal 10-15 GB de folga (instalador do Nmap + margem operacional do Windows; o script já falhou uma vez em campo por disco quase cheio)
- [ ] **Adaptador de rede ativo** (cabo com link ou Wi-Fi conectado) no momento da execução — sem isso não há o que detectar

---

## 2. O que o script usa (ferramentas e técnicas)

- [ ] **Nmap** — motor de descoberta de rede e scan de portas/serviços/SO
- [ ] **Npcap** — driver de captura de pacotes no Windows, instalado junto com o Nmap, necessário para varredura ARP/broadcast/OS-fingerprint
- [ ] **`System.Net.NetworkInformation.NetworkInterface`** (.NET) — detecção de adaptadores de rede e IPs, **sem depender do WMI/CIM** (que pode estar corrompido em alguns PCs corporativos)
- [ ] **`Get-AuthenticodeSignature`** (PowerShell/.NET) — validação de assinatura digital do instalador baixado, antes de executá-lo
- [ ] **UAC / `Start-Process -Verb RunAs`** — autoelevação de privilégios
- [ ] **JSON** (`ConvertTo-Json`/`ConvertFrom-Json`) — persistência da "memória" de redes já escaneadas
- [ ] **XML** (saída nativa do Nmap `-oX`) — formato intermediário de onde o script extrai os dados pro CSV/relatórios
- [ ] **TLS 1.2 / 1.3** forçados explicitamente (`[Net.ServicePointManager]::SecurityProtocol`) — evita falha de download em PCs mais antigos que não usam TLS 1.2 por padrão
- [ ] **HTML + CSS inline** (sem dependência externa/CDN) — geração do relatório visual, roda 100% offline

---

## 3. Fluxo de execução, passo a passo (ordem real)

1. [ ] Força TLS 1.2/1.3 na sessão do PowerShell
2. [ ] Verifica se está rodando como Administrador — se não, **se autoeleva** (relança a si mesmo elevado) e encerra a instância não-elevada
3. [ ] Procura o `nmap.exe`: primeiro no PATH do sistema, depois numa pasta `nmap\` ao lado do script
4. [ ] Se não encontrar: descobre a versão mais recente em `nmap.org/download.html`, baixa o instalador oficial dessa versão, **valida a assinatura digital**, instala silenciosamente (`/S`), confirma que o executável existe depois de instalar. Se já encontrou uma instalação existente, checa (no máximo 1x/semana, throttle em `atualizacao_nmap.json`) se há versão mais nova e atualiza sozinho quando houver
4.5. [ ] Tenta adicionar o `nmap.exe`/pasta do Npcap às exclusões do Windows Defender (`Add-MpPreference`) — reduz lentidão/instabilidade do NIS durante o scan; se não conseguir (política corporativa), avisa e segue mesmo assim
5. [ ] Cria a pasta `resultados\` se ainda não existir
6. [ ] **Se `-Rede` não foi passado:** detecta a(s) rede(s) local(is) automaticamente via .NET, com espera de até ~30s (tentando a cada 3s) caso o DHCP ainda não tenha terminado de atribuir IP
7. [ ] Compara a(s) rede(s) detectada(s) com o histórico em `redes_conhecidas.json`:
   - Se **todas** já são conhecidas e `-Forcar` não foi passado → avisa e **encerra sem escanear**
   - Se há rede(s) **nova(s)** → prossegue só com as novas (ou com todas, se `-Forcar`)
8. [ ] Para cada adaptador físico envolvido: roda a checagem de **DHCP não autorizado** (resolve o nome de interface que o Nmap reconhece via `nmap --iflist`, casando pelo IP; roda `nmap --script broadcast-dhcp-discover --script-timeout 20s`, com saída ao vivo no console e limite de 20s pra não travar esperando resposta que não vem)
9. [ ] Para cada faixa, roda uma **descoberta de hosts vivos** (`nmap -sn -T4`, via ARP em rede local) — até 3 tentativas se o XML sair corrompido. Constrói a lista de IPs vivos encontrados
9.1. [ ] Dispara **um `nmap.exe` de scan profundo por faixa, todos ao mesmo tempo** (via `Start-Process`, não bloqueante, sem passar por `cmd.exe`), mirando **só os IPs vivos** da faixa (via `-iL`, nunca a faixa CIDR inteira), cada um com saída redirecionada para um arquivo temporário próprio; enquanto os processos rodam, o script desenha uma **tabela de log com bordas** no console (uma linha por evento de cada faixa — fase iniciada, marco de %, conclusão), com a linha da fase em andamento sendo **reescrita no próprio lugar** (via posicionamento absoluto do cursor) a cada ~300ms, e congelada como linha permanente quando a fase muda ou a faixa termina. Se um processo falhar (código de saída != 0) ou passar de 90 minutos numa única tentativa (watchdog de tempo de parede — protege contra o processo "rastejar" sem terminar nem cair), é reiniciado automaticamente, até 5 tentativas por faixa, sem nunca abandonar host nenhum
10. [ ] Lê o XML gerado e monta uma linha por host ativo (`status=up`), extraindo IP, MAC, fabricante, hostname, portas abertas, SO estimado. Se o XML de uma faixa saiu corrompido (processo morreu no meio da escrita, mesmo após esgotar as tentativas), essa faixa é pulada com aviso — as demais continuam normalmente
11. [ ] Classifica cada host em um **Tipo Provável** (roteador/switch, PC/servidor, fabricante de contrato, MAC aleatório, etc.) cruzando o fabricante do MAC com listas conhecidas + checagem bit a bit do MAC
12. [ ] Roda uma **confirmação extra de impressoras** (`nmap -Pn -p 9100,631,515`) só nos hosts cujo fabricante é ambíguo (chip de rede genérico tipo Realtek) — o `-Pn` evita falso negativo em impressoras com ICMP/ping bloqueado
13. [ ] Roda uma **checagem de serviços UDP + nome NetBIOS** (`nmap -sU -Pn -p <lista> --script nbstat`) contra todos os hosts já encontrados — soma portas UDP confirmadas abertas em `PortasAbertas` e preenche `Hostname` via NetBIOS quando o DNS reverso não resolve
14. [ ] Testa **de verdade** (não supõe) se a rede tem DNS reverso funcional, resolvendo uma amostra de até 8 IPs ativos via `[Net.Dns]::GetHostEntry` a partir do próprio PC do scan
15. [ ] Marca a(s) faixa(s) recém-escaneada(s) como "conhecida(s)" em `redes_conhecidas.json`
16. [ ] Atualiza o **histórico de dispositivos** (`historico_dispositivos.json`, por MAC/IP) e calcula quantos são novos nas últimas 24h/7 dias/30 dias
17. [ ] Atualiza o **log de confiabilidade** (`log_confiabilidade.json`) com quantas faixas precisaram de retry nesta execução
18. [ ] Exporta o inventário completo em CSV (com checkpoints intermediários após cada etapa de enriquecimento, para não perder dados se uma etapa posterior falhar)
19. [ ] Gera o **resumo em texto** (contagens, alertas, top fabricantes/SOs, diagnóstico de DNS reverso, dispositivos novos, confiabilidade da execução)
20. [ ] Gera o **relatório visual em HTML** (cards, tabelas, destaques, diagnóstico de DNS reverso, dispositivos novos, confiabilidade da execução)
21. [ ] Mostra a mensagem final de conclusão e **pausa a janela** (não fecha sozinha) até apertar Enter — tanto em sucesso quanto em erro

---

## 4. Funções do script (referência técnica)

| Função | Responsabilidade |
|---|---|
| `Aguardar-Saida` | Mantém a janela do console aberta no fim da execução (sucesso ou erro) |
| `Test-Administrador` | Verifica se o processo atual tem privilégio de administrador |
| `Get-CaminhoRedesConhecidas` / `Get-RedesConhecidas` / `Save-RedeConhecida` | Leitura/escrita da "memória" de redes já escaneadas (`redes_conhecidas.json`) |
| `Get-ProximoNumeroRegistro` | Incrementa e persiste o número de registro sequencial da execução (`registro_scans.json`) |
| `Get-NomeComputadorCompleto` | Resolve o nome completo (FQDN) do computador de origem, com fallback para o nome curto do Windows |
| `Test-DnsReversoDisponivel` | Testa de verdade (resolução PTR real) se a rede tem DNS reverso funcional, contra uma amostra de IPs ativos |
| `Invoke-NmapCapturado` | Roda o Nmap capturando stdout+stderr juntos sem deixar avisos em stderr virarem erro fatal do PowerShell (ver seção 12) |
| `Get-VersaoNmapMaisRecente` | Descobre a versão mais recente do Nmap disponível em `nmap.org/download.html` (regex sobre o link do instalador) |
| `Get-VersaoNmapInstalada` | Lê a versão do `nmap.exe` já instalado (`nmap -V`) |
| `Test-DeveChecarAtualizacaoNmap` / `Save-ChecagemAtualizacaoNmap` | Throttle semanal da checagem de atualização (`atualizacao_nmap.json`) |
| `Install-Nmap` | Baixa (a versão mais recente, ou uma especificada), valida assinatura digital, e instala o Nmap silenciosamente |
| `Add-ExcecaoDefenderNmap` | Tenta adicionar o Nmap/Npcap às exclusões do Windows Defender (reduz lentidão/instabilidade do NIS); falha silenciosamente com aviso se não puder (política corporativa) |
| `Get-HostsVivos` | Fase 1 do scan: descoberta rápida de hosts vivos numa faixa via `nmap -sn` (ARP), com até 3 tentativas |
| `Update-HistoricoDispositivos` | Atualiza `historico_dispositivos.json` (1ª/última vez visto por MAC/IP) e calcula quantos dispositivos são novos nas últimas 24h/7d/30d |
| `Save-LogConfiabilidade` | Registra, por execução, quantas faixas precisaram de retry e quantas tentativas extras foram gastas (`log_confiabilidade.json`, últimas 50 execuções) |
| `Test-EquipamentoDeRede` | Verifica se o fabricante do MAC bate com marca conhecida de roteador/switch/AP |
| `Test-MacLocalmenteAdministrado` | Checa o bit "locally administered" do MAC (identifica endereço aleatório/spoofed) |
| `Get-TipoProvavel` | Classifica o tipo provável de dispositivo (roteador, PC, impressora, ODM, etc.) |
| `Confirm-Impressoras` | Roda scan extra nas portas 9100/631/515 (com `-Pn`) para confirmar impressoras suspeitas |
| `Confirm-ServicosUdp` | Roda scan UDP focado (DNS/DHCP/SNMP/mDNS/SSDP/etc. + script `nbstat`) para completar `PortasAbertas` e preencher `Hostname` via NetBIOS |
| `Resolve-NomeInterfaceNmap` | Descobre o nome de interface que o Nmap usa (`eth0`, `eth1`...) casando pelo IP, já que difere do nome do Windows |
| `Find-DhcpNaoAutorizado` | Roda a sondagem de broadcast DHCP e alerta se houver mais de um servidor respondendo |
| `New-RelatorioResumo` | Gera o resumo em texto (`resumo_<data>.txt`), incluindo o tempo total da execução |
| `ConvertTo-TextoHtml` | Escapa caracteres especiais (`&`, `<`, `>`, `"`) para uso seguro dentro do HTML |
| `New-RelatorioHtml` | Gera o relatório visual em HTML (`relatorio_<data>.html`), incluindo o tempo total da execução |
| `Format-Decorrido` | Formata um `TimeSpan` como `mm:ss` ou `hh:mm:ss` para exibição |
| `Enable-AnsiConsole` | Habilita processamento de sequências ANSI/VT no console via P/Invoke (`SetConsoleMode`); define `$script:corSuportada` |
| `Format-TextoTruncado` / `Format-TextoCentralizado` | Cortam e/ou centralizam texto numa largura fixa de coluna, usados por toda a tabela de log |
| `Format-BordaTabela` | Desenha as linhas de borda da tabela (topo/meio/base) com caracteres Unicode de desenho de caixa |
| `Format-LinhaTabelaLog` | Formata uma linha de dados (ou o cabeçalho) da tabela de log, colorida por rede/status |
| `Write-LinhaLogParalelo` | Escreve ou reescreve (no mesmo lugar, via `[Console]::SetCursorPosition`) uma linha da tabela de log |
| `Invoke-NmapsComLogParalelo` | Dispara um Nmap por faixa em paralelo e conduz a tabela de log ao vivo até todas terminarem (ver seção 13) |
| `ConvertTo-CIDR` | Calcula o endereço de rede (CIDR) a partir de um IP + tamanho de prefixo |
| `Wait-RedesLocaisAtivas` / `Get-RedesLocaisAtivas` | Detecção da(s) rede(s) local(is) ativa(s), com espera/retentativa para dar tempo ao DHCP |

---

## 5. Todos os arquivos que o script cria ou usa

| Arquivo | Onde | Quando é criado | O que contém |
|---|---|---|---|
| `redes_conhecidas.json` | Pasta do script | Após o primeiro scan completo | Lista de redes CIDR já escaneadas, com data da 1ª e última vez, e quantas vezes |
| `registro_scans.json` | Pasta do script | Na primeira execução | Contador do número de registro sequencial (`UltimoNumero`) |
| `atualizacao_nmap.json` | Pasta do script | Na primeira checagem de atualização | Data/hora da última checagem de versão do Nmap (throttle semanal) |
| `historico_dispositivos.json` | Pasta do script | Após o primeiro scan completo | 1ª/última vez visto de cada dispositivo (por MAC, ou IP se MAC ausente), quantas vezes visto |
| `log_confiabilidade.json` | Pasta do script | Na primeira execução | Histórico das últimas 50 execuções: faixas com retry, tentativas extras, faixas com erro final |
| `nmap\nmap.exe` | Pasta do script (opcional) | Manual, se você quiser evitar o download automático | Cópia local do Nmap |
| `resultados\descoberta_<rede>_<data>.xml` | resultados\ | Temporário, durante a fase 1 (descoberta) de cada faixa | Saída do `nmap -sn` — **apagado automaticamente** logo após a leitura |
| `resultados\vivos_<rede>_<data>.txt` | resultados\ | Temporário, durante a fase 2 (scan profundo) de cada faixa | Lista de IPs vivos usada como alvo via `-iL` — **apagado automaticamente** ao final da faixa |
| `resultados\scan_<rede>_<data>.xml` | resultados\ | A cada faixa escaneada (em paralelo, fase 2) | Saída bruta e completa do Nmap (formato XML) |
| `resultados\dhcp_check_<adaptador>_<data>.txt` | resultados\ | A cada checagem de DHCP | Saída bruta do script NSE `broadcast-dhcp-discover` |
| `resultados\confirmacao_impressoras_<data>.txt` | resultados\ | Quando há suspeitos de impressora | Saída do scan focado nas portas 9100/631/515 |
| `resultados\udp_check_<data>.txt` | resultados\ | Ao final de cada execução (se houver hosts ativos) | Saída do scan UDP focado + script `nbstat` |
| `resultados\inventario_<data>.csv` | resultados\ | Ao final de cada execução | Inventário completo, uma linha por dispositivo — abre no Excel |
| `resultados\resumo_<data>.txt` | resultados\ | Ao final de cada execução | Resumo agregado em texto simples, incluindo número de registro, computador e tempo total da execução |
| `resultados\relatorio_<data>.html` | resultados\ | Ao final de cada execução | Relatório visual, pronto para apresentação/impressão em PDF |
| `resultados\scan_<rede>_<data>.progresso.log` / `.progresso.err.log` | resultados\ | Temporário, durante o scan de cada faixa (em paralelo) | stdout/stderr do Nmap redirecionados para leitura da tabela de log — **apagados automaticamente** ao final de cada faixa escaneada (não ficam no disco depois) |

---

## 6. Todas as colunas do inventário (CSV / relatório)

| Coluna | Origem / como é calculada |
|---|---|
| `Rede` | Faixa CIDR escaneada (a que esse host pertence) |
| `IP` | Endereço IPv4 do host, direto do XML do Nmap |
| `Hostname` | Nome resolvido pelo Nmap via DNS reverso; se vazio, `Confirm-ServicosUdp` tenta preencher via nome NetBIOS (script `nbstat`, só Windows) |
| `MAC` | Endereço físico da placa de rede |
| `Fabricante` | Fabricante do MAC (OUI), conforme a base de dados interna do Nmap |
| `PossivelEquipamentoRede` | `SIM` se `Fabricante` bate com uma marca de roteador/switch/AP conhecida |
| `TipoProvavel` | Classificação detalhada — ver tabela na seção 7 |
| `SO_Estimado` | Palpite de sistema operacional (`-O` do Nmap), pode vir vazio se não houver confiança suficiente |
| `PortasAbertas` | Lista de `porta/protocolo(serviço versão)` TCP do scan principal + portas UDP confirmadas `open` de `Confirm-ServicosUdp` |
| `DataScan` | Timestamp da execução (`yyyy-MM-dd_HHmmss`) |
| `NumeroRegistro` | Número de registro sequencial da execução, de `Get-ProximoNumeroRegistro` (`registro_scans.json`) |
| `ComputadorOrigem` | Nome completo (FQDN) ou nome curto do computador de origem, de `Get-NomeComputadorCompleto` |

---

## 7. Regras de classificação do `TipoProvavel`

Ordem de avaliação (a primeira regra que bater, vale):

1. [ ] MAC com bit "locally administered" ligado → **VM / dispositivo com MAC aleatorio**
2. [ ] Fabricante vazio ou não identificado → **(fabricante nao identificado)**
3. [ ] Fabricante em lista de marcas de rede (TP-Link, Mercusys, D-Link, Netgear, Ubiquiti, MikroTik, Cisco, **Huawei Technologies** (não "Huawei" sozinho — ver seção 14, bug #8), Aruba, Ruckus, Ruijie, Zyxel, Tenda, Intelbras, Multilaser, Linksys, Fortinet, Juniper, H3C, Extreme Networks, DrayTek, Actiontec, Arris, Sagemcom, Technicolor, Sercomm, Askey) → **Roteador / AP / Switch**
4. [ ] Fabricante em lista de chip de rede genérico (Realtek) → **Possivel impressora (verificar porta 9100/631/515)**, depois refinado pela `Confirm-Impressoras` para **Impressora confirmada** ou **PC provavel**
5. [ ] Fabricante em lista de fabricante de contrato/ODM (Foxconn/Hon Hai, Pegatron, Quanta, Compal, Wistron, Flextronics, Jabil) → **Possivel (fabricante de contrato/ODM)**
6. [ ] Fabricante em lista de marca só-celular/tablet (Samsung Electronics, Xiaomi, OPPO, vivo Mobile, OnePlus, Motorola Mobility, LG Electronics, Murata, TCT Mobile, Sony Mobile, HMD Global, Honor Device, Realme) → **Celular / Tablet (provavel)**
7. [ ] Fabricante em lista de marca de PC/servidor (Gigabyte, ASUSTek, ASRock, MSI, Dell, Hewlett Packard, Lenovo, Supermicro, Elitegroup, Biostar, Intel Corporate) → **PC / Servidor**
8. [ ] Fabricante em lista ambígua PC-ou-móvel (Apple, Google, Huawei Device) → usa `SO_Estimado` como desempate: `iOS`/`iPhone`/`iPad`/`Android` → **Celular / Tablet (provavel)**; `Mac OS`/`macOS` → **PC / Servidor**; sem SO estimado → **PC ou Celular/Tablet (verificar manualmente)**
9. [ ] Nenhuma regra bateu → **Nao classificado**

---

## 8. O que o script verifica antes de agir (segurança)

- [ ] **Assinatura digital do instalador do Nmap** — só instala se assinado por `Insecure.Com LLC`, `Nmap Project` ou `Nmap Software LLC`; aborta e apaga o arquivo se a assinatura não bater
- [ ] **Código de saída do instalador** — confere se a instalação terminou sem erro antes de seguir
- [ ] **Existência do executável** após instalar, nos dois caminhos padrão (`Program Files` e `Program Files (x86)`)
- [ ] **Elevação de administrador** feita via prompt nativo do UAC do Windows (não contorna nem burla o UAC de nenhuma forma)

---

## 9. Parâmetros disponíveis

| Parâmetro | Uso |
|---|---|
| (nenhum) | Detecta a rede automaticamente e escaneia |
| `-Rede <CIDR>[,<CIDR>...]` | Força uma ou mais faixas específicas, pulando a detecção automática (ex: `-Rede 10.5.20.0/24` ou `-Rede 10.5.20.0/24,192.168.1.0/24`). Múltiplas faixas são escaneadas em paralelo |
| `-Forcar` | Ignora a memória de redes já conhecidas e escaneia mesmo assim |

---

## 10. Limitações conhecidas (resumo — detalhes no LEIA-ME.md)

- [ ] Só enxerga o(s) segmento(s) de rede aos quais o PC de origem está fisicamente conectado — redes totalmente isoladas (sem rota até esse ponto) não aparecem
- [ ] Não mapeia topologia física (qual cabo entra em qual porta de switch) — só mostra dispositivos com IP ativo
- [ ] Detecção de SO é um palpite estatístico, não garantido
- [ ] Classificação de tipo de dispositivo (`TipoProvavel`) é heurística baseada em fabricante/MAC — não é uma identificação definitiva, é um direcionador para investigação manual
- [ ] Um host individualmente problemático (alta perda de pacote/latência) pode fazer sua faixa demorar bem mais que o normal (minutos a até ~1h em casos extremos observados) — não trava o restante da rede, mas também não é abandonado (ver seção 15)

---

## 11. Checklist operacional resumido

**Antes de rodar:**
- [ ] Autorização de TI/segurança documentada
- [ ] Notebook com espaço em disco de sobra
- [ ] Conectado no ponto de rede física correto

**Durante:**
- [ ] Rodar via `powershell -ExecutionPolicy Bypass -File .\scan-rede.ps1` (nunca duplo-clique)
- [ ] Aceitar o UAC quando aparecer
- [ ] Não fechar a janela antes da mensagem final "Concluído!"

**Depois:**
- [ ] Conferir `resultados\relatorio_<data>.html` (visual) e `inventario_<data>.csv` (dados)
- [ ] Guardar os arquivos de cada execução para comparar histórico depois
- [ ] Investigar fisicamente qualquer linha marcada como equipamento de rede suspeito ou alerta de DHCP duplicado

---

## 12. Auditoria técnica (16/09/2026)

Revisão linha a linha do script inteiro + testes reais contra o Nmap (incluindo contra o caminho real do projeto, com espaço e acento no diretório).

### Bugs corrigidos

- [x] **🔴 Crítica — falha silenciosa no scan principal.** `Invoke-NmapComBarraDeProgresso` originalmente montava o comando do Nmap como uma string única e mandava pro `cmd.exe /c`. O PowerShell reaplica suas próprias regras de citação por cima de uma string já citada manualmente, corrompendo o parsing sempre que havia mais de um caminho com espaço na linha de comando (ex: a própria pasta do projeto, `...\Matheus Coelho\...`). Resultado: o `cmd.exe` falhava (exit code 1) sem nenhum arquivo de log ou XML sendo criado, e o script seguia adiante achando que só não tinha achado nada (`"O Nmap nao gerou saida... Pulando."`) — um relatório final de "0 dispositivos" sem pista nenhuma da causa real.
  - **Correção:** reescrita para invocar `nmap.exe` diretamente via `Start-Process` (sem `cmd.exe`), usando `-RedirectStandardOutput`/`-RedirectStandardError` nativos. Isso revelou um segundo problema: `Start-Process -ArgumentList` não cita automaticamente argumentos com espaço (diferente do operador `&` com splatting usado no resto do script) — o caminho do XML estava sendo cortado no primeiro espaço (`C:\Users\Matheus` em vez do caminho completo), e o Nmap reportava `Failed to open XML output file ... Acesso negado`. Corrigido citando manualmente cada elemento do array de argumentos antes de passar para `-ArgumentList`.
  - **Verificação:** testado isoladamente contra `192.168.111.1` usando o caminho real da pasta `resultados\` do projeto (com espaço + "á"); confirmado XML gerado corretamente e barra de progresso funcionando ao vivo (fase, %, ETA dinâmico) do início ao fim.
- [x] **🟡 Média — falso negativo em confirmação de impressora.** `Confirm-Impressoras` não usava `-Pn`, então uma impressora com ICMP/ping bloqueado seria erroneamente classificada como "PC provável" por não responder à redescoberta de host. Corrigido adicionando `-Pn` (os hosts já foram confirmados ativos no scan principal).

### Verificado e confirmado correto
- [x] Autoelevação via UAC já citava argumentos corretamente (confirmado por múltiplas execuções bem-sucedidas reais)
- [x] `Resolve-NomeInterfaceNmap`, `Find-DhcpNaoAutorizado` e `Confirm-Impressoras` usam `Invoke-NmapCapturado` (operador `&` com splatting), que não tem o mesmo risco de citação do `Start-Process`
- [x] Nenhum outro uso de `Start-Process` no script tem o padrão de risco encontrado no item crítico acima

### Backlog identificado (não crítico, não corrigido nesta rodada)
- [ ] Sem timeout de segurança geral para o processo do Nmap no scan principal — se travar por motivo externo (driver, rede), a tabela de log ficaria parada esperando aquele processo terminar sozinho
- [ ] `Aguardar-Saida` assume execução interativa (console real); impede automação totalmente não-interativa (ex: tarefa agendada) sem adicionar um parâmetro tipo `-SemPausa` no futuro
- [ ] Checagem por fabricante literalmente `"Unknown"`/`"desconhecido"` em `Get-TipoProvavel` é código morto — o Nmap nunca emite esse texto, só omite o atributo quando não reconhece o OUI (já coberto pelo `-not $fabricante`). Inofensivo, mas redundante
- [ ] `[Console]::SetCursorPosition` (usado por `Write-LinhaLogParalelo` para reescrever a linha "viva") assume janela larga o bastante (~110 colunas) e buffer que não role para fora durante a execução; em janela muito estreita ou sessão extremamente longa, cai (com `try/catch`) para o comportamento de só acrescentar linha nova, sem travar

---

## 13. Evolução técnica — 16/09/2026, sessão 2 (paralelismo real + log em tabela)

Depois da auditoria da seção 12, o mecanismo de progresso evoluiu de uma barra sequencial (uma faixa por vez) para paralelismo real com log em tabela. Resumo técnico:

- **Paralelismo:** `Invoke-NmapsComLogParalelo` dispara um `Start-Process` por faixa (não bloqueante) e acompanha todos simultaneamente num único loop de polling (~300ms), em vez do antigo `foreach` sequencial com `Invoke-NmapComBarraDeProgresso` (função removida).
- **Renderização:** tabela com bordas Unicode (`Format-BordaTabela`), colunas de largura fixa (hora/rede/fase/%/eta/status), coloridas por rede (`$script:paletaCoresRede`, cicla ciano/roxo/amarelo/azul) e por status (`iniciado`=ciano, `em andamento`=amarelo, `concluido`=verde, `erro`=vermelho).
- **Linha "viva":** enquanto uma fase está em andamento, a linha correspondente é reescrita no próprio lugar via `[Console]::SetCursorPosition` (guardado em `$t.LinhaViva` por tarefa) a cada volta do loop — inclusive a coluna "hora", que atualiza a cada ~300ms independente de o Nmap ter reportado percentual novo (heartbeat), para parecer um cronômetro de verdade em vez de ficar travada entre leituras.
- **Congelamento:** ao detectar mudança de fase ou término do processo, a linha viva é reescrita uma última vez com o resultado final (`concluido`) e uma nova linha permanente é aberta para a próxima fase — preserva o histórico completo rolável no console.
- **Fallback sem ANSI:** quando `$script:corSuportada` é falso (console sem VT, ou saída redirecionada), a tabela ainda é desenhada (bordas Unicode não dependem de ANSI), mas sem cor e sem reescrita no lugar — cada evento vira uma linha nova.

### Bugs corrigidos nesta evolução (todos via reprodução real, não só revisão)

- [x] **🔴 Crítica — script inteiro parava de rodar** (`TerminatorExpectedAtEndOfString`) ao introduzir os caracteres de bloco (`█`/`░`) da barra visual. Causa: `scan-rede.ps1` não tinha BOM UTF-8; sem BOM, o parser do PowerShell lê o arquivo pela codepage ANSI do sistema, e os bytes daqueles caracteres colidem com "aspas inteligentes" Unicode (`U+2018`/`U+2019`) que o parser aceita como delimitador alternativo de string literal, quebrando a sintaxe do arquivo inteiro. Corrigido adicionando BOM UTF-8 (`New-Object System.Text.UTF8Encoding($true)`).
- [x] **🟡 Média — spinner/barra apareciam como retângulos vazios ("tofu")** no console real, mesmo sem erro de execução. Causa: codepage do console não estava em UTF-8. Corrigido com `chcp.com 65001` + `[Console]::OutputEncoding = [Text.Encoding]::UTF8` logo após a autoelevação, com fallback silencioso (`try/catch`) se o console não suportar.
- [x] **🟡 Média — fase longa do Nmap desalinhava a tabela inteira.** Nomes como `Parallel DNS resolution of N hosts.` (mais compridos que a coluna) estouravam para o lado e quebravam o alinhamento de todas as colunas seguintes daquela linha. Corrigido com `Format-TextoTruncado`, aplicado antes de qualquer padding/centralização.
- [x] **🟢 Baixa — `-Rede` com múltiplas faixas não sobrevivia à autoelevação.** `Start-Process -File` (usado no relançamento elevado) não faz o split automático de vírgula que o parser do PowerShell faz numa invocação direta (`-Rede a,b`). Corrigido normalizando `$Rede` logo após o `param()` (`$_ -split ','`), cobrindo os dois casos de entrada.

---

## 14. Auditoria completa — 16/09/2026, rodada 3 (precisão para apresentação executiva)

Revisão linha a linha de todo o script (~1400 linhas), motivada pelo requisito explícito de que os resultados seriam apresentados à diretoria — toda alegação no relatório precisa ser sustentável por dado real, não suposição.

### Bugs corrigidos

- [x] **🔴 Crítica (introduzido na sessão anterior) — celulares Huawei classificados como roteador.** `$FabricantesEquipamentoRede` tinha só `"Huawei"` (substring), que também batia em `"Huawei Device Co."` (fabricante de celular vindo do Nmap) — e a checagem de equipamento de rede roda ANTES da checagem de celular/tablet na ordem de `Get-TipoProvavel`. Corrigido trocando para `"Huawei Technologies"` (string mais específica, só bate na divisão de redes/roteadores da empresa).
- [x] **🟡 Média — confirmação de impressora falhava silenciosamente com DNS reverso.** A regex `Nmap scan report for (\S+)` em `Confirm-Impressoras` capturava o **hostname**, não o IP, quando a linha vinha como `Nmap scan report for impressora.local (192.168.1.5)` (formato do Nmap quando o DNS reverso resolve um nome). A comparação seguinte (`$_.IP -eq $ipBloco`) nunca batia nesses casos, deixando o dispositivo preso em "Possível impressora" para sempre. Corrigido para extrair o IP de dentro dos parênteses quando presente, ou direto quando não há hostname. Testado com os dois casos isoladamente.
- [x] **🟢 Baixa — mensagem de retry cortada na tabela.** `"erro de driver, tentando de novo"` (33 caracteres) estourava a coluna de status (24 caracteres). Encurtado para `"erro driver, retry..."`.

### Resposta à pergunta "o script identifica IPs não autorizados?"

**Não — e isso precisa constar explicitamente na apresentação.** O script faz inventário + heurística de suspeita (fabricante de equipamento de rede, DHCP duplicado), não comparação contra uma lista de dispositivos autorizados. Não existe baseline de MACs esperados. A afirmação defensável é "N dispositivos ativos, X com características de equipamento de rede não documentado, Y com DHCP duplicado" — não "N dispositivos não autorizados". Implementar uma baseline real (`dispositivos_autorizados.json` comparado contra o inventário) foi avaliado e **adiado a pedido do usuário**; fica como item de backlog.

### Melhorias de cobertura implementadas

- [x] **`Confirm-ServicosUdp`** (nova função): scan UDP focado (portas 53/67/68/123/135/137/138/139/161/162/177/427/500/514/520/631/1900/3702/5353/5355) contra todos os hosts já ativos, com `-Pn`. Só soma em `PortasAbertas` portas com estado `open` confirmado (nunca `open|filtered`, que é ambíguo) — decisão deliberada para não inflar o relatório com dados incertos.
- [x] **Hostname via NetBIOS**: mesma função roda `--script nbstat` (porta 137/udp) e extrai `NetBIOS name:` da saída para preencher `Hostname` em máquinas Windows quando o DNS reverso não resolve.
- [x] **`Test-DnsReversoDisponivel`** (nova função): testa reversão PTR real (`[Net.Dns]::GetHostEntry`) contra até 8 IPs ativos, a partir do PC que roda o scan, e reporta resultado concreto (quantos resolveram, quais servidores DNS estão configurados) no resumo e no HTML — substitui suposição por dado verificável.
- [x] **Avaliado e adiado a pedido:** `-Pn` no scan TCP principal (garantiria que nenhum host com todas as sondagens de descoberta bloqueadas ficasse fora do inventário) — mantido desligado pelo custo de tempo numa faixa /24 completa.

---

## 15. Evolução técnica — 21-22/09/2026 (persistência, auto-atualização e correção do travamento de horas)

Motivada por relatos reais em campo: execuções passando de 2h e travando com `Got nsock WRITE error #10107` (erro de driver Npcap), exigindo fechamento manual da janela. Objetivo explícito: mais persistência (nunca desistir de um host), mais velocidade, mais precisão — tudo refletido no relatório.

### Recursos novos
- [x] **Auto-atualização do Nmap**: `Get-VersaoNmapMaisRecente` faz scraping de `nmap.org/download.html`; `Test-DeveChecarAtualizacaoNmap`/`Save-ChecagemAtualizacaoNmap` fazem throttle semanal (`atualizacao_nmap.json`); `Install-Nmap` aceita a versão como parâmetro. Testado ao vivo contra o site real, atualizando 7.95 → 7.991 com sucesso.
- [x] **Exceção automática no Windows Defender**: `Add-ExcecaoDefenderNmap` tenta `Add-MpPreference -ExclusionProcess`/`-ExclusionPath` para o Nmap e a pasta do Npcap; falha silenciosamente (com aviso) se a máquina for gerenciada por política corporativa.
- [x] **Histórico de dispositivos** (`Update-HistoricoDispositivos`, `historico_dispositivos.json`): rastreia 1ª/última vez visto por MAC (fallback IP), calcula quantos dispositivos são novos nas últimas 24h/7d/30d. Testado isoladamente em duas execuções simuladas, contagem e persistência corretas.
- [x] **Log de confiabilidade** (`Save-LogConfiabilidade`, `log_confiabilidade.json`): histórico das últimas 50 execuções (faixas com retry, tentativas extras, faixas com erro final), com tendência histórica exibida no relatório.
- [x] **Proteção contra XML corrompido**: `[xml]$scanXml = Get-Content $xmlPath -Raw` envolvido em try/catch — antes, um XML truncado (processo do Nmap morto no meio da escrita) lançava exceção que, com `$ErrorActionPreference = "Stop"` no escopo do script, derrubava a execução **inteira**, descartando os resultados já coletados de todas as outras faixas. Bug real reproduzido em campo (`Fim de arquivo inesperado... elementos nao fechados: nmaprun`).
- [x] **Persistência de 1 para 5 tentativas**: `TentouNovamente` (booleano, só para erro `nsock`) virou `TentativasFeitas` (contador, até `$maxTentativasNmap = 5`), retentando para **qualquer** código de saída não-zero — decisão explícita do usuário ("não quero que o scanner desista").
- [x] **`--host-timeout` avaliado e rejeitado** a pedido explícito do usuário: abandonaria hosts genuinamente lentos (mas reais) do inventário, o que conflita direto com o objetivo de "trazer todos os hosts".

### Diagnóstico do travamento de horas (root cause), passo a passo

Cada hipótese foi testada contra a rede real de produção, não só inferida por leitura de código:

1. **Descartada — escala da rede.** `nmap -sn` na `/24` inteira (256 endereços) achou os hosts reais em ~7,5s. A rede não é grande o bastante para explicar horas de execução.
2. **Descartada — os hosts vivos isoladamente.** Rodar o comando de produção exato (`-T4 -O -sV --osscan-guess`) só contra os hosts já confirmados vivos completou em ~6min, sem erro.
3. **Confirmada — sondar endereço morto em profundidade.** Reproduzindo o cenário real (scan profundo na `/24` inteira, incluindo os ~240 endereços sem host) reproduziu o travamento: **5h44min**, falha após esgotar as 5 tentativas, `nsock WRITE error #10107` recorrente. Sondagem profunda contra endereço morto gera muito mais retransmissão/timeout do que contra um host vivo respondendo — multiplicado por ~240 endereços, sobrecarrega o Npcap.
4. **Primeira correção (arquitetura de 2 fases)**: `Get-HostsVivos` (fase 1, `-sn`/ARP) descobre todos os vivos primeiro; a fase 2 (`-O -sV --osscan-guess -Pn -iL <lista>`) escaneia só esses, nunca mais tocando endereço morto. Testado: reduziu o problema, mas ainda travava — desta vez isolado a **dois hosts específicos** da rede (não mais o padrão geral de sondar endereço morto).
5. **Segunda correção (taxa de envio)**: `-T4` mandava pacote mais rápido do que o Npcap aguentava nesta máquina, mesmo com o alvo já reduzido aos vivos. Trocado por `--max-retries 2 --max-rate 150`. Testado de ponta a ponta contra os 10 hosts vivos reais da rede: **10/10 com relatório completo, zero ocorrência de `nsock` em todo o log**. Um host individualmente problemático ainda pode ser bem mais lento que os demais (observado: ~59min para 2 hosts específicos, contra ~4min para os outros 8) — mas termina, não trava.
6. **Watchdog de tempo por tentativa**: uma primeira tentativa de detecção de travamento comparava fase+percentual entre iterações do loop (se não mudasse por N minutos, mata o processo). **Descartada por teste real** — o percentual reportado pelo Nmap pode oscilar levemente mesmo travado, driblando essa checagem; o scan continuou preso além do limite configurado sem disparar o watchdog. Substituída por um corte simples de **tempo de parede por tentativa** (`$tetoTentativaMin = 90`): mais simples, e comprovadamente eficaz nos testes (disparou corretamente aos 30/60min nos testes anteriores à correção da taxa de envio).

### Metodologia de validação
Cada mudança foi testada contra a faixa `/24` de produção real através de um harness que carrega só as funções do script (sem disparar a autoelevação UAC) e invoca a função de scan paralelo diretamente — não apenas revisão de código. Resultados numéricos de cada iteração (tempo total, hosts encontrados, tentativas gastas, presença/ausência de erro de driver) foram conferidos antes de cada mudança seguinte ser aplicada.

---

**Criado por: Matheus Coelho** — autor deste projeto (script `scan-rede.ps1` e toda a documentação associada).
