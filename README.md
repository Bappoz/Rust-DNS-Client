# Cliente DNS (MX) em Rust

[![CI](https://github.com/Bappoz/Rust-DNS-Client/actions/workflows/ci.yml/badge.svg)](https://github.com/Bappoz/Rust-DNS-Client/actions/workflows/ci.yml)

Cliente DNS minimo, sem biblioteca de resolucao, que consulta registros MX via UDP
(com fallback para TCP em respostas truncadas).

## Uso

```sh
cargo run -- <dominio> <ip_servidor_dns> [-v|--verbose]
cargo run -- unb.br 8.8.8.8
```

Sem `-v`, o `stderr` so recebe erros reais. Com `-v`/`--verbose`, o cliente
imprime logs de diagnostico (pacote enviado, tentativas, truncamento, cache).

## Testes

```sh
cargo test                  # unitarios, sem rede
cargo test -- --ignored     # integracao ponta a ponta, requer rede
```

Os testes de `tests/integration.rs` consultam servidores DNS publicos reais
(`8.8.8.8`) e por isso sao `#[ignore]` por padrao. **Precisam de acesso a rede e
podem falhar se a infraestrutura externa mudar** (por exemplo, se `unb.br`
trocar de provedor de e-mail ou `fga.unb.br` passar a publicar MX). Cada teste
usa um cache isolado via `DNS_CLIENT_CACHE`.

## CI

`.github/workflows/ci.yml` roda `cargo fmt --check`, `cargo clippy -- -D warnings`
e `cargo test` em push para `main` e em PRs. Os testes de integracao nao rodam no CI.

## Servidor mock local

`tools/dns_mock.py` sobe um servidor UDP em `127.0.0.1:53` (requer privilegio)
para testar o cliente sem rede externa.
