# 🔎 Scanner de Rede Interna (scan-rede.ps1)

**Criado por: [Matheus Coelho](https://github.com/XMatheusCoelhoX)**

Script PowerShell que detecta e mapeia automaticamente toda a rede local, gerando um inventário completo de dispositivos ativos e sinalizando infraestrutura não autorizada (roteadores/switches/APs desconhecidos, servidores DHCP duplicados). Pensado para levantamento de infraestrutura de rede interna sem depender de switches gerenciáveis ou ferramentas caras.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Nmap](https://img.shields.io/badge/Engine-Nmap-brightgreen?logo=nmap)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)

---

## ✨ O que ele faz

- **Detecta a rede local automaticamente** (IP + máscara → CIDR), sem precisar informar nada na mão — funciona em qualquer rede, em qualquer computador, sem valores fixos no código
- **Instala o Nmap sozinho** se não estiver presente, validando a **assinatura digital** do instalador antes de rodar
- **Escaneia toda a rede** (hosts ativos, MAC, fabricante, SO estimado, portas/serviços abertos)
- **Classifica o tipo provável de cada dispositivo** (roteador/switch/AP, PC/servidor, impressora, fabricante de contrato/ODM, MAC aleatório/spoofed) cruzando o fabricante do MAC com listas conhecidas
- **Confirma impressoras automaticamente** via scan de portas específicas (9100/631/515), evitando falsos positivos de fabricantes de chip de rede genérico
- **Detecta servidor DHCP não autorizado** — alerta quando mais de um servidor responde na mesma rede, indício forte de roteador/AP clandestino
- **Lembra o que já escaneou** — pula automaticamente redes já mapeadas em execuções anteriores, útil ao testar vários pontos de rede em sequência
- **Barra de progresso ao vivo** durante scans longos — linha única atualizada em tempo real com fase atual, % concluído e ETA dinâmico, além de um cronômetro do início ao fim da operação completa
- Gera **três formatos de saída**: CSV (planilha), resumo em texto, e um **relatório visual em HTML** pronto para apresentação (exporta direto para PDF)

## 📋 Requisitos

- Windows 10/11 com Windows PowerShell 5.1 (já vem instalado)
- Privilégios de administrador local (o script pede elevação sozinho via UAC)
- Conexão com a internet **apenas na primeira execução** (para baixar o Nmap, caso não esteja instalado)

## 🚀 Uso

```powershell
# Detecta a rede automaticamente e escaneia
powershell -ExecutionPolicy Bypass -File .\scan-rede.ps1

# Força uma faixa de rede específica
powershell -ExecutionPolicy Bypass -File .\scan-rede.ps1 -Rede 10.5.20.0/24

# Escaneia mesmo que a rede já seja conhecida (ignora a memória de execuções anteriores)
powershell -ExecutionPolicy Bypass -File .\scan-rede.ps1 -Forcar
```

Os resultados são salvos em `resultados\` (CSV, resumo em texto, relatório HTML) — essa pasta é ignorada pelo Git (veja `.gitignore`) porque contém dados reais da rede de quem executa.

## 📖 Documentação completa

| Documento | Conteúdo |
|---|---|
| [LEIA-ME.md](LEIA-ME.md) | Explicação passo a passo de tudo que o script faz, checklists de uso e troubleshooting |
| [CHECKLIST-TECNICO.md](CHECKLIST-TECNICO.md) | Referência técnica exaustiva: cada função, cada arquivo gerado, cada regra de classificação |

## ⚠️ Uso responsável

Esta ferramenta faz varredura ativa de rede (descoberta de hosts, scan de portas, sondagem de DHCP). **Use apenas em redes que você possui ou tem autorização explícita para avaliar.** Scans de rede não autorizados podem violar políticas internas de TI/segurança e, dependendo da jurisdição, legislação local. O autor não se responsabiliza por uso indevido.

## 📄 Licença

Distribuído sob a licença MIT — veja [LICENSE](LICENSE) para mais detalhes.

---

**Criado por: [Matheus Coelho](https://github.com/XMatheusCoelhoX)**
