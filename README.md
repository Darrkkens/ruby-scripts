# Auditoria Defensiva para Debian 12 em Ruby

Projeto CLI em Ruby para auditoria basica de seguranca em uma VPS Linux Debian 12, com foco em triagem defensiva e verificacao educativa. A ferramenta nao executa exploracao ofensiva nem tentativas de ataque.

## Estrutura

```text
.
|-- main.rb
|-- modules/
|   |-- cve_scanner.rb
|   |-- docker_audit.rb
|   |-- fail2ban_audit.rb
|   |-- miner_audit.rb
|   |-- nmap_audit.rb
|   |-- rootkit_audit.rb
|   `-- subdomain_scanner.rb
|-- utils/
|   |-- cve_baseline.rb
|   |-- nmap_helper.rb
|   |-- output.rb
|   |-- shell.rb
|   `-- validators.rb
`-- logs/
```

## O que a ferramenta faz

- Deteccao basica de rootkits com integracao opcional a `rkhunter`, `chkrootkit`, `debsums` e `lsof`.
- Verificacao de instalacao, status e jails do Fail2Ban.
- Triagem de crypto miners por uso de CPU, nomes suspeitos, conexoes tipicas e persistencia simples.
- Auditoria basica de Docker: daemon exposto, `docker.sock`, containers ativos, privilegios, portas e mounts criticos.
- Scanner simples de subdominios por wordlist, com validacao DNS opcional e Nmap opcional nas portas comuns.
- Scanner basico de CVEs por banners detectados com Nmap e cruzamento com uma base heuristica local.
- Integracao direta com Nmap para portas abertas e versoes de servicos.

## Dependencias no Debian 12

### Base minima

```bash
sudo apt update
sudo apt install -y ruby-full nmap
```

### Ferramentas opcionais recomendadas

```bash
sudo apt install -y fail2ban docker.io chkrootkit rkhunter debsums lsof
```

Observacoes:

- `fail2ban` e `docker.io` so sao necessarios se esses servicos fizerem parte do host auditado.
- Para inspecionar Docker com detalhes, execute como `root` ou com um usuario no grupo `docker`.
- O grupo `docker` concede acesso equivalente a root. Use isso com cuidado.

## Como executar

```bash
ruby main.rb
```

Ao iniciar, o programa pergunta se a sessao deve ser salva em `logs/`. Depois disso, apresenta um menu interativo com os modulos de auditoria.

## Resumo dos modulos

### 1. Deteccao basica de rootkits

- Usa `rkhunter` e `chkrootkit` quando disponiveis.
- Procura alteracoes simples em binarios com `debsums`.
- Lista arquivos deletados ainda em uso com `lsof`.
- Busca executaveis em `/tmp`, `/var/tmp` e `/dev/shm`.

### 2. Status do Fail2Ban

- Confirma se o pacote esta instalado.
- Consulta se o servico esta ativo e habilitado no boot.
- Lista jails ativas.
- Mostra contagem resumida de bans por jail.

### 3. Deteccao basica de crypto miners

- Mostra processos com uso alto de CPU.
- Busca nomes e argumentos suspeitos.
- Procura conexoes em portas comuns de mining pools.
- Procura referencias suspeitas em cron e systemd.

### 4. Verificacao de Docker vulneravel

- Confirma se Docker existe no host.
- Verifica `systemctl`, `daemon.json`, listeners TCP e `docker.sock`.
- Lista containers em execucao.
- Analisa `--privileged`, namespaces do host, `CapAdd`, portas sensiveis e mounts criticos.

### 5. Scanner de subdominios

- Recebe um dominio.
- Testa subdominios comuns por wordlist.
- Opcionalmente valida DNS.
- Opcionalmente roda Nmap nas portas `22,80,443,8080,8443`.

### 6. Scanner basico de CVEs

- Recebe um alvo autorizado.
- Usa `nmap -sV` para detectar servicos e versoes.
- Cruza resultados com uma base heuristica local de ramos/versoes antigas.
- Serve como triagem inicial, nao como validacao definitiva de CVEs.

### 7. Integracao com Nmap

- Modo rapido para portas comuns.
- Modo com deteccao de servicos.
- Modo com portas especificas informadas no menu.

## Observacoes de seguranca

- A ferramenta e voltada para auditoria defensiva e educativa.
- Nao ha codigo de exploracao, brute force, bypass ou ataque.
- Use Nmap somente contra ativos sob sua administracao ou com autorizacao explicita.
- Achados baseados em banner podem gerar falso positivo, especialmente em Debian com backports de seguranca.
- Rodar o projeto como `root` melhora a visibilidade de processos, Docker, Fail2Ban e ferramentas como `rkhunter`.

## Limitacoes

- Nao substitui EDR, SIEM, IDS/IPS ou hardening formal.
- Nao consulta bancos de CVE online; a triagem de CVE e local e heuristica.
- O scanner de subdominios usa apenas wordlist basica, sem enumeracao passiva externa.
- A verificacao de rootkits depende da disponibilidade de ferramentas do sistema para cobertura melhor.
- A deteccao de crypto miners e baseada em sinais comuns; malware discreto pode passar despercebido.

## Expansoes futuras sugeridas

- Exportacao em JSON.
- Perfis de auditoria completos por tipo de servidor.
- Relatorios comparativos por data.
- Mais regras locais para versoes e exposicoes conhecidas.
