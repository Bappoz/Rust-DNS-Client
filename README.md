# Cliente DNS em Rust — Trabalho 01 (FRC)

[![CI](https://github.com/Bappoz/Rust-DNS-Client/actions/workflows/ci.yml/badge.svg)](https://github.com/Bappoz/Rust-DNS-Client/actions/workflows/ci.yml)

Cliente DNS para a disciplina Fundamentos de Redes de Computadores (FGA/UnB,
Prof. Tiago Alves). Recebe um nome de domínio e o IP de um servidor DNS, envia
uma consulta **MX** recursiva por **UDP/53** e imprime o servidor de e-mail do
domínio.

A mensagem DNS é montada e interpretada byte a byte pelo próprio código
(`src/dns/`), sem biblioteca de resolução de nomes e **sem nenhuma dependência
externa**: só a biblioteca padrão do Rust. A comunicação usa o socket UDP de
`std::net`.

## Integrantes

Trabalho feito em trio.

| Nome | Matrícula |
| --- | --- |
| Lucas Andrade Zanetti | 241039645 |
| Matheus Eiki | |
| Giovanna Felipe | |

## 1. Sistema operacional

Desenvolvido e testado em **Linux x86_64**: Omarchy 4.0.4 (base Arch Linux),
kernel 7.2.5. O CI do repositório compila e roda os testes unitários em
`ubuntu-latest`. Não foi testado em Windows nem em macOS.

## 2. Ambiente de desenvolvimento

| Item | Versão |
| --- | --- |
| Linguagem | Rust, edição 2024 |
| Compilador | `rustc` 1.99.0 |
| Gerenciador de build | `cargo` 1.99.0 |
| Editor | NeoVim 0.12 |
| Dependências externas | nenhuma |

**Versão mínima do Rust: 1.88**, declarada em `Cargo.toml` (`rust-version`). O
código usa edição 2024 e `if let` encadeado (*let chains*), que não compilam em
versões anteriores. O `rustc` empacotado por
distribuições mais antigas pode estar abaixo disso; nesse caso, instale o
toolchain atual com [rustup](https://rustup.rs). A compilação foi verificada
com as versões 1.93.0 e 1.99.0.

## 3. Como construir

```sh
cargo build --release
```

O executável é gerado em `target/release/my-client`.

A compilação **não precisa de acesso à internet**: o projeto não tem
dependências para baixar.

## 4. Como executar

```
./target/release/my-client <dominio> <ip_servidor_dns>
```

- `<dominio>`: nome cuja entrada MX se procura (primeiro argumento).
- `<ip_servidor_dns>`: endereço **IPv4** do servidor DNS (segundo argumento). A
  porta é sempre a 53.

Também é possível compilar e executar em um passo só:

```sh
cargo run --release -- unb.br 8.8.8.8
```

O resultado vai para a saída padrão (`stdout`). O código de saída é `0` quando a
entrada MX é encontrada e `1` em qualquer outro caso.

## 5. Telas (instruções de uso)

A aplicação é de linha de comando; as "telas" são as saídas no terminal. As
transcrições abaixo são execuções reais do binário.

### 5.1 Os quatro cenários do enunciado

Resolução bem-sucedida:

```console
$ ./target/release/my-client unb.br 8.8.8.8
unb.br <> unb-br.mail.protection.outlook.com
```

Nome de domínio não existe (o servidor responde NXDOMAIN):

```console
$ ./target/release/my-client imagdaskdasdasj.br 1.1.1.1
Dominio imagdaskdasdasj.br nao encontrado
```

Domínio existe, mas não possui entrada MX:

```console
$ ./target/release/my-client fga.unb.br 8.8.8.8
Dominio fga.unb.br nao possui entrada MX
```

Servidor não existe ou não atendeu. A mensagem aparece depois de 3 tentativas
com 2 segundos de espera cada (cerca de 6 segundos no total):

```console
$ ./target/release/my-client unb.br 1.2.3.4
Nao foi possível coletar entrada MX para unb.br
```

### 5.2 Erros de uso

Essas mensagens vão para a saída de erro (`stderr`), com código de saída `1`.

```console
$ ./target/release/my-client
uso: ./target/release/my-client <dominio> <ip_servidor_dns> [-v|--verbose] [--backoff] [--cache] [--tcp] [--type <A|AAAA|CNAME|NS|TXT|MX>]

$ ./target/release/my-client unb.br dns.google
ip do servidor DNS invalido: invalid socket address syntax
```

### 5.3 Opções além do enunciado

O comportamento pedido no enunciado é o padrão: sem nenhuma opção, o cliente
faz apenas consulta MX, somente por UDP, com 3 tentativas de 2 segundos, e
envia a consulta ao servidor em toda execução. As opções abaixo são extras e só
mudam o comportamento quando informadas.

| Opção | Efeito |
| --- | --- |
| `-v`, `--verbose` | Imprime na `stderr` o pacote enviado em hexadecimal e as tentativas. |
| `--type <TIPO>` | Consulta outro tipo de registro (`A`, `AAAA`, `CNAME`, `NS`, `TXT`) em vez de MX. A saída passa a ser `dominio TIPO valor`, uma linha por registro. |
| `--backoff` | Troca a espera fixa de 2 s por esperas de 1 s, 2 s e 4 s nas três tentativas. |
| `--cache` | Guarda a resposta MX em disco e a reutiliza até o TTL expirar (seção 6.1). |
| `--tcp` | Se o servidor truncar a resposta UDP (bit TC), repete a consulta por TCP na porta 53. |

Com `-v` é possível conferir os campos da consulta exigidos pelo enunciado:

```console
$ ./target/release/my-client unb.br 8.8.8.8 -v
[debug] servidor=8.8.8.8 txid=0xdb4f pacote (24 bytes): db 4f 01 00 00 01 00 00 00 00 00 00 03 75 6e 62 02 62 72 00 00 0f 00 01
[debug] tentativa 1/3
[debug] timeout da tentativa 1/3: 2000ms
unb.br <> unb-br.mail.protection.outlook.com
```

| Bytes | Campo | Valor |
| --- | --- | --- |
| `db 4f` | Transaction ID | aleatório, muda a cada execução |
| `01 00` | Flags | `0x0100` (consulta recursiva) |
| `00 01` | Questions | 1 |
| `00 00 00 00 00 00` | Answer, Authority e Additional RRs | 0 |
| `03 75 6e 62 02 62 72 00` | Name | `unb.br` |
| `00 0f` | Type | MX (15) |
| `00 01` | Class | IN (1) |

Consulta de outro tipo de registro:

```console
$ ./target/release/my-client unb.br 8.8.8.8 --type A
unb.br A 164.41.102.70
```

## 6. Limitações conhecidas

### 6.1 Opções extras

- **`--cache` não distingue o servidor.** A resposta fica em
  `~/.cache/rust-dns-client/cache-v1` (ou em `$XDG_CACHE_HOME`; o caminho pode
  ser trocado pela variável `DNS_CLIENT_CACHE`). A chave é só o domínio e o
  tipo de registro, então, com `--cache`, uma consulta a `unb.br` em `1.2.3.4`
  feita logo depois de uma em `8.8.8.8` devolve a resposta guardada sem enviar
  pacote. Só respostas MX bem-sucedidas são guardadas, e duas execuções
  simultâneas com `--cache` esperam uma pela outra (até 7 s) por causa do
  arquivo de trava.
- **`--tcp` usa `std::net::TcpStream`.** A repetição por TCP é feita uma única
  vez, com tempo limite de 2 s, e uma falha nela encerra o programa com erro na
  `stderr`.
- **`--type`** consulta um único tipo por execução e aceita apenas `A`,
  `AAAA`, `CNAME`, `NS`, `TXT` e `MX`.

### 6.2 Respostas truncadas e nomes acentuados

- **Resposta maior que 512 bytes.** Sem `--tcp`, o cliente usa o que coube no
  datagrama UDP. Se a entrada MX não estiver nessa parte, ele avisa na `stderr`
  (`resposta truncada pelo servidor (bit TC); repita com --tcp`) e imprime
  `Nao foi possível coletar entrada MX`. Esse caminho não é coberto pelos testes
  automatizados: não há um servidor de teste que devolva resposta truncada.
- **Nomes acentuados (IDN)** são convertidos para Punycode por um codificador
  próprio (RFC 3492, em `src/dns/name.rs`). O nome é apenas passado para
  minúsculas antes da conversão: não há normalização Unicode (NFC) nem o
  mapeamento da UTS #46, então um nome digitado com acentos decompostos gera
  uma consulta diferente da forma composta. As mensagens de saída repetem o
  nome como foi digitado.

### 6.3 Protocolo

- **Só o primeiro registro MX é exibido**, na ordem em que o servidor
  respondeu. O campo de preferência do MX é ignorado, então o servidor
  mostrado pode não ser o de maior prioridade.
- **Servidor só por IPv4 literal.** Nomes (`dns.google`) e endereços IPv6 são
  recusados.
- **Sem EDNS0.** Respostas UDP ficam limitadas a 512 bytes.
- **Erros do servidor diferentes de NXDOMAIN** (SERVFAIL, REFUSED, FORMERR)
  são tratados como ausência de resposta: o cliente espera, tenta de novo e
  termina com `Nao foi possível coletar entrada MX`.
- **O tamanho total do nome (255 bytes) não é validado**, apenas o de cada
  rótulo (63 bytes). Um nome longo demais é enviado mesmo assim e a execução
  termina, após as 3 tentativas, em `Nao foi possível coletar entrada MX`.
- **A resposta não é conferida contra a pergunta.** O cliente valida o IP de
  origem, o Transaction ID e o bit de resposta, mas não compara a seção
  Question nem o nome dos registros com o domínio consultado. Também não há
  validação DNSSEC.
- **Transaction ID não criptográfico.** É gerado por um gerador pseudoaleatório
  próprio (SplitMix64) semeado com o relógio e o PID. As três tentativas
  reutilizam o mesmo ID.

### 6.4 Testes

- Os testes de integração (`tests/integration.rs`) consultam `8.8.8.8` e
  dependem de registros de terceiros: falham se `unb.br` deixar de publicar MX
  ou se `fga.unb.br` passar a publicar. Por isso não rodam por padrão.
- O servidor de teste `tools/dns_mock.py` escuta em `127.0.0.1:53`, porta que
  exige privilégio de administrador, e o cliente não tem opção para usar outra
  porta.

## Testes

```sh
cargo test                  # unitários, sem rede
cargo test -- --ignored     # integração contra servidores reais, requer rede
```

Os testes de integração cobrem os quatro cenários do enunciado, incluindo a
execução do quarto cenário com uma resposta já guardada no cache.

## Organização do código

| Arquivo | Conteúdo |
| --- | --- |
| `src/main.rs` | Argumentos, socket UDP, tentativas com tempo limite e mensagens de saída. |
| `src/dns/message.rs` | Cabeçalho e seção Question da consulta; leitura da seção Answer. |
| `src/dns/name.rs` | Codificação do nome em rótulos, Punycode e leitura de nomes com ponteiros de compressão. |
| `src/dns/txid.rs` | Gerador do Transaction ID de 16 bits. |
| `src/dns/cache.rs` | Cache em disco com TTL, usado só com `--cache`. |
| `tests/integration.rs` | Testes de ponta a ponta do binário. |
| `tools/dns_mock.py` | Servidor DNS de teste (Python 3), não faz parte da solução. |
