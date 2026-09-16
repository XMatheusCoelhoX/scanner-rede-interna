# Scanner de Rede Interna — Documentação e Checklist

> **Criado por: Matheus Coelho**
> Este projeto (script + documentação) é de autoria de Matheus Coelho. Ao copiar, adaptar ou redistribuir este material, mantenha esta atribuição.

Script: `scan-rede.ps1`
Objetivo: mapear todos os dispositivos ativos na rede local (IP, MAC, fabricante, SO estimado, portas abertas) para identificar infraestrutura não documentada — ex: cabos de rede extras/pontos não mapeados.

---

## 1. O que o script faz, passo a passo

### Passo 1 — Autoelevação (pedido de Administrador)
Se o PowerShell não estiver rodando como Administrador, o script **reabre a si mesmo** em uma nova janela elevada (dispara o prompt do UAC do Windows) e encerra a janela original.

- **Por quê:** instalar o Nmap/driver Npcap e rodar a detecção de sistema operacional (`-O`) exige privilégios de administrador.
- **O que você vê:** um prompt do Windows perguntando "Deseja permitir que este aplicativo faça alterações no dispositivo?" — precisa clicar **Sim**.
- **Se você clicar Não:** o script para e mostra a mensagem de erro na janela original (a janela fica aberta esperando Enter, não fecha sozinha).

### Passo 2 — Verifica se o Nmap já está instalado
Procura o `nmap.exe` em três lugares, nesta ordem:
1. No PATH do sistema (`Get-Command nmap`)
2. Numa pasta `nmap\` ao lado do próprio script (útil se você copiar o Nmap manualmente para um pen drive)
3. Se não achar em nenhum dos dois, parte para o Passo 3 (instalação automática)

### Passo 3 — Download e instalação automática do Nmap (só se necessário)
1. Baixa o instalador oficial de `https://nmap.org/dist/nmap-7.95-setup.exe` (~34 MB)
2. **Confere a assinatura digital (Authenticode)** do arquivo baixado — só prossegue se o instalador estiver assinado digitalmente por `Insecure.Com LLC` / `Nmap Project` / `Nmap Software LLC`. Isso impede rodar um instalador adulterado (ex: se a rede estiver com algum proxy malicioso no meio do caminho).
3. Roda o instalador em modo silencioso (`/S`), que também instala o driver **Npcap** (necessário para o Nmap capturar pacotes no Windows)
4. Apaga o instalador baixado depois de usar
5. Confirma que o `nmap.exe` existe em `C:\Program Files\Nmap\` ou `C:\Program Files (x86)\Nmap\`

### Passo 4 — Detecção automática da rede local
Usa a API .NET (`System.Net.NetworkInformation.NetworkInterface`) para achar os adaptadores de rede **ativos** (cabo ou Wi-Fi conectado) sem depender do WMI/CIM do Windows (que pode estar corrompido em alguns PCs, causando erro "Classe inválida"), e:
- **Ignora** adaptadores virtuais: Hyper-V, WSL, VPN, VMware/VirtualBox, loopback, Npcap loopback
- **Ignora** IPs de autoconfiguração (169.254.x.x — "sem rede real")
- Para cada adaptador real restante, calcula a faixa de rede (CIDR) a partir do IP + máscara de sub-rede (ex: IP `10.5.20.50` + máscara `255.255.255.0` → faixa `10.5.20.0/24`) — **dinâmico**, nunca fixo no código: se você plugar em outro prédio/ponto e a rede for `10.7.3.0/24` ou qualquer outra, o script detecta essa faixa real automaticamente

Se você acabou de plugar o cabo, o Windows pode levar alguns segundos negociando o IP via DHCP — o script **espera até ~30 segundos**, tentando a cada 3s, antes de desistir. Isso é pensado justamente para o cenário de "cheguei agora, plug no cabo, rodei o script na hora".

Você pode pular essa detecção e forçar uma faixa manualmente com `-Rede 10.5.20.0/24`.

### Passo 4.5 — Comparação com redes já conhecidas (pré-teste automático)
O script guarda, num arquivo `redes_conhecidas.json` ao lado dele, toda faixa CIDR que já escaneou por completo alguma vez (com data da primeira e da última vez).

Toda vez que detecta a rede do ponto onde você plugou, ele compara:
- Se a rede detectada **já é conhecida** (mesmo CIDR de uma execução anterior) → o script **avisa e pula o scan completo automaticamente**, sem gastar tempo. Você só vê uma mensagem tipo `Rede já conhecida ... Scan completo pulado automaticamente`.
- Se a rede é **nova** (nunca vista antes) → prossegue normalmente para o scan completo.
- Se você conectar um cabo que dá numa rede **mista** (alguns adaptadores em rede conhecida, outro em rede nova) → escaneia só a(s) nova(s), avisando quais foram puladas.

Isso automatiza exatamente a "checagem rápida de 10 segundos" (plugar e olhar se o IP já é o conhecido) — não precisa mais fazer isso manualmente cabo por cabo.

Use `-Forcar` para ignorar essa memória e escanear de novo mesmo uma rede já conhecida (útil para reverificações periódicas, tipo "será que apareceu dispositivo novo nessa rede desde a semana passada").

### Passo 5 — Checagem de DHCP não autorizado (só no modo automático)
Para cada adaptador de rede detectado, o script envia uma sondagem de broadcast (`nmap --script broadcast-dhcp-discover`) perguntando "quem distribui IP nessa rede?".

- Se **só 1 servidor** responder → normal, mostra "OK" em verde.
- Se **mais de 1 servidor** responder → mostra **ALERTA** em vermelho. Isso é um forte indício de que alguém plugou um roteador, switch com DHCP, ou ponto de acesso Wi-Fi não autorizado na mesma rede — o cenário mais comum de "cabo clandestino" numa rede sem VLAN.
- O resultado bruto de cada checagem fica salvo em `resultados\dhcp_check_<adaptador>_<data>.txt`.
- A sondagem tem um **limite de 20 segundos** (`--script-timeout 20s`) — se não vier resposta nenhuma nesse tempo, o Nmap desiste sozinho e o script segue em frente, em vez de ficar travado esperando indefinidamente. A saída do Nmap aparece **ao vivo** na tela enquanto roda (não fica escondida até o final).

**Detalhe técnico importante (resolução do nome da interface):** o Nmap no Windows (via driver Npcap) **não reconhece** o nome amigável que o Windows dá ao adaptador (ex: "Ethernet", "Ethernet 2") no parâmetro `-e` — ele usa nomes próprios internos, tipo `eth0`, `eth1`, que variam de PC pra PC e não têm relação nenhuma com o nome que aparece no Painel de Controle. Se o script passasse o nome do Windows direto pro Nmap, a checagem falharia com erro tipo `I cannot figure out what source address to use for device Ethernet`.

Pra resolver isso **em qualquer computador**, sem hardcoded nada, o script:
1. Roda `nmap --iflist` naquele PC, na hora, e lê a lista de interfaces que o Nmap enxerga ali (seja qual for o nome que ele usar)
2. Casa essa lista pelo **endereço IP** do adaptador (que já temos, vem da nossa própria detecção de rede no Passo 4) — o IP é o único identificador confiável em comum entre a visão do Windows e a visão do Nmap
3. Usa o nome que o Nmap devolveu (`eth0`, `eth1`, etc., o que for naquele PC) no `-e`

Se por algum motivo essa resolução falhar (formato de saída inesperado, versão muito diferente de Nmap/Npcap) o script **não trava** — ele avisa e pula só essa checagem específica, seguindo normalmente para o scan principal, que não depende dela.

### Passo 6 — Execução do scan (com barra de progresso ao vivo)
Para cada faixa detectada (ou forçada), roda:

```
nmap -O -sV --osscan-guess --stats-every 3s -oX <arquivo>.xml <faixa>
```

| Flag | O que faz |
|---|---|
| `-O` | Tenta identificar o sistema operacional de cada dispositivo |
| `-sV` | Identifica versão de serviços rodando nas portas abertas |
| `--osscan-guess` | Deixa o palpite de SO mais "flexível" quando não há 100% de certeza |
| `--stats-every 3s` | Faz o Nmap recalcular e reportar percentual/ETA a cada 3 segundos |
| `-oX` | Salva a saída bruta em formato XML (arquivo intermediário — o relatório final em HTML só é gerado depois que **todas** as faixas terminam de escanear) |

O Nmap não roda direto no console — a função `Invoke-NmapComBarraDeProgresso` executa ele em segundo plano (via `Start-Process`, com a saída redirecionada para um arquivo temporário) e desenha **uma única linha viva no terminal**, atualizada no lugar (usando retorno de carro `\r`, sem quebrar linha a cada atualização), mostrando:

```
[decorrido 02:14] Service scan: 66,7% concluido, tempo restante estimado: 0:01:03
```

- **Tempo decorrido**: cronômetro daquela faixa específica, atualizado a cada segundo
- **Fase atual**: qual etapa do Nmap está rodando (`SYN Stealth Scan`, `Service scan`, `NSE`, etc.)
- **% concluído e tempo restante estimado**: recalculado pelo próprio Nmap a cada atualização — varia sozinho conforme a velocidade real do scan muda (fica mais rápido/lento dependendo de quantos hosts respondem, congestionamento da rede, etc.)

Separadamente, também existe um cronômetro da **execução inteira** (do início ao fim — inclui checagem de DHCP, todas as faixas, confirmação de impressoras e geração dos relatórios), mostrado na mensagem final e salvo no resumo/HTML.

> **Nota de auditoria (corrigido):** a primeira versão dessa barra de progresso tinha um bug de aspas que fazia o scan **falhar silenciosamente** (sem gerar erro nem XML) em qualquer caminho de pasta com espaço — que é exatamente o caso deste projeto (`...\Matheus Coelho\...`). Duas causas foram encontradas e corrigidas: (1) enviar o comando pronto como uma string única para `cmd.exe` fazia o PowerShell requotar por cima e quebrar o parsing; (2) depois de trocar para invocar o Nmap diretamente, descobriu-se que `Start-Process -ArgumentList` **não** coloca aspas automáticas em argumentos com espaço (diferente do operador `&` usado no resto do script) — corrigido citando manualmente cada argumento antes de passar. Testado e confirmado funcionando com o caminho real do projeto.

### Passo 7 — Geração do inventário (CSV)
Lê o XML gerado e monta uma tabela com uma linha por dispositivo ativo encontrado:

| Coluna | Descrição |
|---|---|
| Rede | Faixa CIDR escaneada |
| IP | Endereço IP do dispositivo |
| Hostname | Nome de rede, se resolvido |
| MAC | Endereço físico da placa de rede |
| Fabricante | Fabricante identificado pelo prefixo do MAC (OUI) — ex: "TP-Link", "Dell", "Hewlett Packard" |
| PossivelEquipamentoRede | "SIM" se o fabricante bate com marcas típicas de roteador/switch/AP (TP-Link, Mercusys, Ubiquiti, MikroTik, Cisco, etc.) — vale checar essas linhas primeiro |
| TipoProvavel | Classificação mais detalhada do tipo de dispositivo (ver Passo 7.5) |
| SO_Estimado | Palpite de sistema operacional do Nmap |
| PortasAbertas | Lista de portas abertas com serviço/versão detectados |
| DataScan | Timestamp da execução |

Salva em: `resultados\inventario_<data>_<hora>.csv` (abre direto no Excel).
O XML bruto de cada faixa também fica salvo em `resultados\`, caso precise reprocessar depois.

### Passo 7.5 — Classificação do tipo provável de dispositivo + confirmação de impressoras
Além do fabricante bruto, o script tenta adivinhar o **tipo** de cada dispositivo cruzando o OUI do MAC com listas de fabricantes conhecidos, e credita o bit "locally administered" do próprio MAC (identifica MAC aleatório/spoofed, comum em celulares e VMs):

| TipoProvavel | Quando aparece |
|---|---|
| `Roteador / AP / Switch` | Fabricante é marca de rede conhecida (TP-Link, Mercusys, Ubiquiti, D-Link, Cisco, etc.) |
| `PC / Servidor` | Fabricante é marca de placa-mãe/sistema (Gigabyte, ASUS, Dell, HP, Lenovo, MSI, etc.) |
| `Possivel (fabricante de contrato/ODM)` | Fabricante é uma montadora de contrato (Foxconn/Hon Hai, Pegatron, Quanta, etc.) — eles fabricam hardware pra dezenas de marcas diferentes (impressoras, roteadores, notebooks white-label), então o tipo real fica ambíguo só pelo OUI |
| `Impressora confirmada (porta de impressao aberta)` | Fabricante tem chip de rede genérico (ex: Realtek — comum tanto em impressoras quanto em PCs), **e** o script confirmou via scan extra que a porta 9100 (RAW/JetDirect), 631 (IPP) ou 515 (LPD) está aberta |
| `PC provavel (chip Realtek/generico, sem porta de impressao)` | Mesmo fabricante ambíguo acima, mas **nenhuma** porta de impressão respondeu — ou seja, é provavelmente só um PC comum com aquele chip de rede onboard, não uma impressora de verdade |
| `VM / dispositivo com MAC aleatorio` | O MAC tem o bit "locally administered" ligado — endereço gerado/aleatorizado, não veio de um fabricante real. Comum em celulares com privacidade de MAC ativada, VMs, containers |
| `(fabricante nao identificado)` | Nmap não achou esse prefixo de MAC na base de fabricantes (OUI raro ou desatualizado na base local) |
| `Nao classificado` | Fabricante reconhecido, mas não bate com nenhuma das listas acima |

**Confirmação automática de impressoras:** depois do scan principal, o script roda um scan extra e focado (`nmap -Pn -p 9100,631,515`) só nos hosts marcados como "possível impressora" pelo fabricante ambíguo, pra confirmar de verdade antes de você sair procurando uma impressora que na real é só um PC. O `-Pn` pula a redescoberta de host (esses IPs já foram confirmados ativos no scan principal) — sem ele, uma impressora com ping/ICMP bloqueado seria incorretamente classificada como "PC provável" por não responder à sondagem de host. Detalhes salvos em `resultados\confirmacao_impressoras_<data>.txt`.

### Nota técnica — evitando falsos erros do PowerShell com avisos do Nmap
Toda chamada ao Nmap que **captura a saída** (em vez de deixá-la aparecer direto no console) passa pela função `Invoke-NmapCapturado`. Isso existe por um motivo específico: com `$ErrorActionPreference = "Stop"` ativo no script inteiro, qualquer linha que o Nmap escreva no stream de erro (`stderr`) — mesmo um aviso inofensivo como `WARNING: No targets were specified, so 0 hosts scanned.` (normal em sondagens de broadcast, que não precisam de alvo) — seria promovida pelo PowerShell a uma **exceção fatal**, fazendo o script achar que deu erro quando na verdade só era um aviso comum. A função reverte temporariamente essa preferência só durante a chamada ao Nmap, evitando esse falso positivo.

---

## 2. Estrutura de pastas gerada

```
scanner-rede\
├── scan-rede.ps1              <- o script
├── LEIA-ME.md                 <- este documento
├── redes_conhecidas.json      <- memoria das redes ja escaneadas (criado automaticamente)
├── nmap\                      <- opcional: coloque aqui o Nmap se quiser evitar o download automático
│   └── nmap.exe
└── resultados\                <- criado automaticamente na primeira execução
    ├── scan_<rede>_<data>.xml               <- saida bruta do Nmap
    ├── dhcp_check_<adaptador>_<data>.txt     <- resultado da checagem de DHCP nao autorizado
    ├── confirmacao_impressoras_<data>.txt    <- resultado do scan de confirmacao de impressoras
    ├── inventario_<data>.csv                <- inventario completo (Excel)
    ├── resumo_<data>.txt                    <- resumo em texto
    └── relatorio_<data>.html                <- relatorio visual para apresentacao (abrir no navegador, Ctrl+P -> PDF)
```

---

## 3. Checklist — antes de rodar em um PC de outro prédio/setor

- [ ] **Autorização documentada** com TI/segurança da informação para fazer o levantamento nessa rede específica (mesmo sendo você mesmo o responsável — evita mal-entendido com sistemas de monitoramento/IDS que podem alertar sobre "scan não autorizado")
- [ ] Confirmar que o PC de destino tem **conexão com a internet** (necessário só na primeira execução, para baixar o Nmap — depois disso ele fica instalado e as próximas execuções não precisam de internet)
- [ ] Confirmar que o PC de destino tem pelo menos **~10-15 GB de espaço livre em disco** (download do instalador + margem de segurança para o sistema)
- [ ] Ter certeza de que está **conectado à rede correta** no PC de destino (cabo de rede daquele prédio, não VPN/Wi-Fi de outra rede)
- [ ] Rodar via `powershell -ExecutionPolicy Bypass -File .\scan-rede.ps1` (não dar duplo-clique direto no `.ps1` — por padrão o Windows abre `.ps1` no Bloco de Notas em vez de executar)
- [ ] Aceitar o prompt de UAC quando aparecer (elevação de administrador)
- [ ] Aguardar a mensagem final "Concluído! N dispositivos ativos encontrados"
- [ ] Conferir o CSV gerado em `resultados\` antes de sair do PC/desconectar do AnyDesk
- [ ] Guardar os CSVs de diferentes execuções/datas para **comparar histórico** — um dispositivo/MAC novo que não estava em uma execução anterior é o sinal de alerta para infraestrutura não mapeada

## 4. Checklist — se o script "não funcionar" (não fizer nada / fechar sozinho)

- [ ] Rode a partir do `powershell.exe`, nunca por duplo-clique no `.ps1` (senão abre no editor de texto e nada executa)
- [ ] Confirme que **não está fechando a janela sozinho** — o script agora sempre pausa no final ("Pressione Enter para fechar"), tanto em sucesso quanto em erro. Se a janela sumir sem essa mensagem, o problema é anterior à execução do script em si (ex: política de execução do PowerShell bloqueando, ou antivírus removendo o arquivo antes de rodar)
- [ ] Verifique o **espaço em disco** (`Get-Volume` no PowerShell) — se estiver praticamente cheio, o download/instalação do Nmap falha silenciosamente
- [ ] Verifique se o **antivírus/EDR corporativo** não removeu o arquivo `.ps1` ou bloqueou a execução — o script baixa e instala um `.exe` automaticamente, o que algumas soluções de segurança podem marcar como comportamento suspeito ("dropper"). Se isso acontecer, considere pedir para a TI colocar a pasta do script em exceção/allowlist, ou instalar o Nmap manualmente antes e colocar o `.exe` na pasta `nmap\` ao lado do script (assim ele pula a etapa de download)
- [ ] Se o UAC aparecer e você clicar **Não** (ou demorar demais e ele expirar), o script para com uma mensagem de erro clara na janela original — leia a mensagem antes de tentar de novo

## 5. Limitações conhecidas

- O script mapeia dispositivos **com IP na rede** — não mostra topologia física (qual switch/porta cada cabo entra). Para isso, use LLDP/CDP nos switches gerenciáveis, ou a tela de "topologia"/tabela de MAC address do painel de administração deles.
- A versão do Nmap está fixada em `7.95` no script — se uma versão mais nova for necessária no futuro, atualize a variável `$versao` dentro da função `Install-Nmap`.
- Detecção de SO (`-O`) é um **palpite** baseado em características da pilha TCP/IP — não é 100% garantido, principalmente em dispositivos IoT/embarcados (impressoras, câmeras, etc.).
- **Importante — o que o script NÃO consegue detectar:** ele só enxerga o(s) segmento(s) de rede que o próprio PC onde ele roda está fisicamente conectado. Se um "cabo clandestino" leva a uma rede **totalmente isolada** (com gateway/DHCP próprios, sem nenhuma ligação com a rede corporativa — ex: um roteador com chip 4G próprio, ou uma segunda entrada de internet), nenhum scan de rede consegue ver isso, porque não existe rota de rede até lá. Isso só é detectável fisicamente (testador de cabo/tone tracer nos pontos suspeitos) ou verificando se há circuitos de internet extras entrando no prédio.
- Se o "cabo clandestino" estiver **conectado/emendado na mesma rede existente** (o cenário mais comum quando não há VLAN) — por exemplo, alguém plugou um switch ou roteador Wi-Fi extra num ponto de rede para ganhar mais portas/Wi-Fi — o script **consegue** flagrar isso de duas formas: (1) o equipamento aparece na lista de dispositivos, e a coluna `PossivelEquipamentoRede` marca "SIM" se o fabricante do MAC for de uma marca de rede; (2) se esse equipamento também distribuir IP via DHCP próprio, a checagem do Passo 5 vai alertar sobre múltiplos servidores DHCP respondendo.

---

## 6. Auditoria técnica e plano de correção

Auditoria completa do script (revisão linha a linha + testes reais contra o Nmap, incluindo contra o caminho real do projeto com espaço/acento) feita em 16/09/2026.

### Encontrado e corrigido

| # | Severidade | Problema | Causa raiz | Correção |
|---|---|---|---|---|
| 1 | 🔴 Crítica | Scan principal podia falhar **silenciosamente** (sem erro, sem XML, relatório final mostrando "0 dispositivos") em qualquer pasta com espaço no caminho — inclusive a pasta padrão deste projeto | A barra de progresso ao vivo enviava o comando do Nmap como uma string única pro `cmd.exe`; o PowerShell reaplicava suas próprias regras de aspas por cima da string já formatada, corrompendo o comando | Reescrito para chamar o `nmap.exe` diretamente via `Start-Process` (sem `cmd.exe`), com cada argumento citado manualmente antes de passar (`Start-Process -ArgumentList` não cita automaticamente, diferente do operador `&` usado no resto do script). Testado e confirmado com o caminho real do projeto |
| 2 | 🟡 Média | Impressora com ping/ICMP bloqueado podia ser classificada incorretamente como "PC provável" | O scan de confirmação de impressora (portas 9100/631/515) não tinha `-Pn`, então tentava redescobrir o host antes de escanear as portas | Adicionado `-Pn` — os hosts já foram confirmados ativos no scan principal, não precisa redescobrir |
| 3 | 🟢 Baixa (já corrigida em rodada anterior) | Avisos inofensivos do Nmap em `stderr` (ex: `WARNING: No targets were specified`) eram promovidos a erro fatal pelo PowerShell | `$ErrorActionPreference = "Stop"` no escopo do script afeta qualquer captura de `stderr` via `2>&1` | Função `Invoke-NmapCapturado` reverte a preferência de erro localmente, só durante a chamada ao Nmap |

### Verificado e confirmado correto (sem ação necessária)
- Autoelevação via UAC (`Start-Process -Verb RunAs`) já citava os argumentos corretamente
- Resolução de nome de interface (`Resolve-NomeInterfaceNmap`) e checagem de DHCP, ambas usando `Invoke-NmapCapturado`/operador `&`, não têm o mesmo risco de aspas do item #1
- Nenhum outro uso de `Start-Process` no script tem o padrão de risco do item #1

### Backlog (identificado, não crítico, não corrigido nesta rodada)
- Sem timeout de segurança geral se o processo do Nmap travar por algum motivo externo (driver, rede) durante o scan principal — hoje a barra de progresso ficaria rodando indefinidamente até o processo terminar sozinho
- `Aguardar-Saida` (pausa no final com "Pressione Enter") assume execução interativa; se alguém tentar rodar o script de forma totalmente automatizada/agendada (sem console interativo), essa pausa bloquearia indefinidamente — não é um problema para o uso pretendido (execução manual, interativa), mas impede automação futura sem um parâmetro tipo `-SemPausa`
- Um trecho de código em `Get-TipoProvavel` checa por fabricante literalmente igual a `"Unknown"`/`"desconhecido"`, mas o Nmap nunca emite esse texto (ele só omite o atributo quando não reconhece o fabricante) — código inofensivo mas nunca executado na prática, poderia ser removido em uma limpeza futura

---

**Criado por: Matheus Coelho** — autor deste projeto (script `scan-rede.ps1` e toda a documentação associada).
