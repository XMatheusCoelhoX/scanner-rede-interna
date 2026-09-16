# Checklist Técnico Completo — scan-rede.ps1

> **Criado por: Matheus Coelho**
> Este projeto (script + documentação) é de autoria de Matheus Coelho. Ao copiar, adaptar ou redistribuir este material, mantenha esta atribuição.

Documento de referência exaustivo: tudo que o script usa, tudo que ele faz, e como ele faz. Complementa o [LEIA-ME.md](LEIA-ME.md) (mais narrativo) com uma visão em checklist, pensada para consulta rápida e auditoria.

---

## 1. Requisitos e dependências

- [ ] **Sistema operacional:** Windows (usa APIs .NET/Win32 específicas do Windows — não roda em Linux/Mac)
- [ ] **PowerShell:** Windows PowerShell 5.1 (built-in em qualquer Windows 10/11) — não precisa do PowerShell 7/Core
- [ ] **Privilégios de administrador local** — o script se autoeleva sozinho (dispara UAC), mas a conta precisa ter direito de virar admin
- [ ] **Nmap 7.x + Npcap** — instalado automaticamente pelo script se não existir; pode também ser pré-instalado ou colocado manualmente na pasta `nmap\`
- [ ] **Conexão com a internet** — necessária **somente** se o Nmap ainda não estiver instalado (para baixar o instalador, ~34 MB). Execuções seguintes no mesmo PC não precisam de internet
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
4. [ ] Se não encontrar: baixa o instalador oficial de `nmap.org`, **valida a assinatura digital**, instala silenciosamente (`/S`), confirma que o executável existe depois de instalar
5. [ ] Cria a pasta `resultados\` se ainda não existir
6. [ ] **Se `-Rede` não foi passado:** detecta a(s) rede(s) local(is) automaticamente via .NET, com espera de até ~30s (tentando a cada 3s) caso o DHCP ainda não tenha terminado de atribuir IP
7. [ ] Compara a(s) rede(s) detectada(s) com o histórico em `redes_conhecidas.json`:
   - Se **todas** já são conhecidas e `-Forcar` não foi passado → avisa e **encerra sem escanear**
   - Se há rede(s) **nova(s)** → prossegue só com as novas (ou com todas, se `-Forcar`)
8. [ ] Para cada adaptador físico envolvido: roda a checagem de **DHCP não autorizado** (resolve o nome de interface que o Nmap reconhece via `nmap --iflist`, casando pelo IP; roda `nmap --script broadcast-dhcp-discover --script-timeout 20s`, com saída ao vivo no console e limite de 20s pra não travar esperando resposta que não vem)
9. [ ] Para cada faixa de rede a escanear: roda `nmap -O -sV --osscan-guess --stats-every 10s -oX <arquivo>.xml <faixa>` (o `--stats-every` imprime progresso ao vivo a cada 10s durante o scan)
10. [ ] Lê o XML gerado e monta uma linha por host ativo (`status=up`), extraindo IP, MAC, fabricante, hostname, portas abertas, SO estimado
11. [ ] Classifica cada host em um **Tipo Provável** (roteador/switch, PC/servidor, fabricante de contrato, MAC aleatório, etc.) cruzando o fabricante do MAC com listas conhecidas + checagem bit a bit do MAC
12. [ ] Roda uma **confirmação extra de impressoras** (`nmap -p 9100,631,515`) só nos hosts cujo fabricante é ambíguo (chip de rede genérico tipo Realtek)
13. [ ] Marca a(s) faixa(s) recém-escaneada(s) como "conhecida(s)" em `redes_conhecidas.json`
14. [ ] Exporta o inventário completo em CSV
15. [ ] Gera o **resumo em texto** (contagens, alertas, top fabricantes/SOs)
16. [ ] Gera o **relatório visual em HTML** (cards, tabelas, destaques)
17. [ ] Mostra a mensagem final de conclusão e **pausa a janela** (não fecha sozinha) até apertar Enter — tanto em sucesso quanto em erro

---

## 4. Funções do script (referência técnica)

| Função | Responsabilidade |
|---|---|
| `Aguardar-Saida` | Mantém a janela do console aberta no fim da execução (sucesso ou erro) |
| `Test-Administrador` | Verifica se o processo atual tem privilégio de administrador |
| `Get-CaminhoRedesConhecidas` / `Get-RedesConhecidas` / `Save-RedeConhecida` | Leitura/escrita da "memória" de redes já escaneadas (`redes_conhecidas.json`) |
| `Install-Nmap` | Baixa, valida assinatura digital, e instala o Nmap silenciosamente |
| `Test-EquipamentoDeRede` | Verifica se o fabricante do MAC bate com marca conhecida de roteador/switch/AP |
| `Test-MacLocalmenteAdministrado` | Checa o bit "locally administered" do MAC (identifica endereço aleatório/spoofed) |
| `Get-TipoProvavel` | Classifica o tipo provável de dispositivo (roteador, PC, impressora, ODM, etc.) |
| `Confirm-Impressoras` | Roda scan extra nas portas 9100/631/515 para confirmar impressoras suspeitas |
| `Resolve-NomeInterfaceNmap` | Descobre o nome de interface que o Nmap usa (`eth0`, `eth1`...) casando pelo IP, já que difere do nome do Windows |
| `Find-DhcpNaoAutorizado` | Roda a sondagem de broadcast DHCP e alerta se houver mais de um servidor respondendo |
| `ConvertTo-CIDR` | Calcula o endereço de rede (CIDR) a partir de um IP + tamanho de prefixo |
| `Wait-RedesLocaisAtivas` / `Get-RedesLocaisAtivas` | Detecção da(s) rede(s) local(is) ativa(s), com espera/retentativa para dar tempo ao DHCP |
| `ConvertTo-TextoHtml` | Escapa caracteres especiais (`&`, `<`, `>`, `"`) para uso seguro dentro do HTML |
| `New-RelatorioResumo` | Gera o resumo em texto (`resumo_<data>.txt`) |
| `New-RelatorioHtml` | Gera o relatório visual em HTML (`relatorio_<data>.html`) |

---

## 5. Todos os arquivos que o script cria ou usa

| Arquivo | Onde | Quando é criado | O que contém |
|---|---|---|---|
| `redes_conhecidas.json` | Pasta do script | Após o primeiro scan completo | Lista de redes CIDR já escaneadas, com data da 1ª e última vez, e quantas vezes |
| `nmap\nmap.exe` | Pasta do script (opcional) | Manual, se você quiser evitar o download automático | Cópia local do Nmap |
| `resultados\scan_<rede>_<data>.xml` | resultados\ | A cada faixa escaneada | Saída bruta e completa do Nmap (formato XML) |
| `resultados\dhcp_check_<adaptador>_<data>.txt` | resultados\ | A cada checagem de DHCP | Saída bruta do script NSE `broadcast-dhcp-discover` |
| `resultados\confirmacao_impressoras_<data>.txt` | resultados\ | Quando há suspeitos de impressora | Saída do scan focado nas portas 9100/631/515 |
| `resultados\inventario_<data>.csv` | resultados\ | Ao final de cada execução | Inventário completo, uma linha por dispositivo — abre no Excel |
| `resultados\resumo_<data>.txt` | resultados\ | Ao final de cada execução | Resumo agregado em texto simples |
| `resultados\relatorio_<data>.html` | resultados\ | Ao final de cada execução | Relatório visual, pronto para apresentação/impressão em PDF |

---

## 6. Todas as colunas do inventário (CSV / relatório)

| Coluna | Origem / como é calculada |
|---|---|
| `Rede` | Faixa CIDR escaneada (a que esse host pertence) |
| `IP` | Endereço IPv4 do host, direto do XML do Nmap |
| `Hostname` | Nome resolvido pelo Nmap (nem sempre disponível) |
| `MAC` | Endereço físico da placa de rede |
| `Fabricante` | Fabricante do MAC (OUI), conforme a base de dados interna do Nmap |
| `PossivelEquipamentoRede` | `SIM` se `Fabricante` bate com uma marca de roteador/switch/AP conhecida |
| `TipoProvavel` | Classificação detalhada — ver tabela na seção 7 |
| `SO_Estimado` | Palpite de sistema operacional (`-O` do Nmap), pode vir vazio se não houver confiança suficiente |
| `PortasAbertas` | Lista de `porta/protocolo(serviço versão)` de todas as portas abertas encontradas |
| `DataScan` | Timestamp da execução (`yyyy-MM-dd_HHmmss`) |

---

## 7. Regras de classificação do `TipoProvavel`

Ordem de avaliação (a primeira regra que bater, vale):

1. [ ] MAC com bit "locally administered" ligado → **VM / dispositivo com MAC aleatorio**
2. [ ] Fabricante vazio ou não identificado → **(fabricante nao identificado)**
3. [ ] Fabricante em lista de marcas de rede (TP-Link, Mercusys, D-Link, Netgear, Ubiquiti, MikroTik, Cisco, Huawei, Aruba, Ruckus, Ruijie, Zyxel, Tenda, Intelbras, Multilaser, Linksys, Fortinet, Juniper, H3C, Extreme Networks, DrayTek, Actiontec, Arris, Sagemcom, Technicolor, Sercomm, Askey) → **Roteador / AP / Switch**
4. [ ] Fabricante em lista de chip de rede genérico (Realtek) → **Possivel impressora (verificar porta 9100/631/515)**, depois refinado pela `Confirm-Impressoras` para **Impressora confirmada** ou **PC provavel**
5. [ ] Fabricante em lista de fabricante de contrato/ODM (Foxconn/Hon Hai, Pegatron, Quanta, Compal, Wistron, Flextronics, Jabil) → **Possivel (fabricante de contrato/ODM)**
6. [ ] Fabricante em lista de marca de PC/servidor (Gigabyte, ASUSTek, ASRock, MSI, Dell, Hewlett Packard, Lenovo, Supermicro, Elitegroup, Biostar, Intel Corporate) → **PC / Servidor**
7. [ ] Nenhuma regra bateu → **Nao classificado**

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
| `-Rede <CIDR>` | Força uma faixa específica, pulando a detecção automática (ex: `-Rede 10.5.20.0/24`) |
| `-Forcar` | Ignora a memória de redes já conhecidas e escaneia mesmo assim |

---

## 10. Limitações conhecidas (resumo — detalhes no LEIA-ME.md)

- [ ] Só enxerga o(s) segmento(s) de rede aos quais o PC de origem está fisicamente conectado — redes totalmente isoladas (sem rota até esse ponto) não aparecem
- [ ] Não mapeia topologia física (qual cabo entra em qual porta de switch) — só mostra dispositivos com IP ativo
- [ ] Detecção de SO é um palpite estatístico, não garantido
- [ ] Classificação de tipo de dispositivo (`TipoProvavel`) é heurística baseada em fabricante/MAC — não é uma identificação definitiva, é um direcionador para investigação manual
- [ ] Versão do Nmap fixada em `7.95` no código (atualizável manualmente na função `Install-Nmap`)

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

**Criado por: Matheus Coelho** — autor deste projeto (script `scan-rede.ps1` e toda a documentação associada).
