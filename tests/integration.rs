//! Testes de integracao ponta a ponta contra servidores DNS publicos.
//!
//! Dependem de rede e de infraestrutura de terceiros, por isso sao `#[ignore]`
//! por padrao. Para rodar: `cargo test -- --ignored`.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const PUBLIC_RESOLVER: &str = "8.8.8.8";
// TEST-NET-1 (RFC 5737): nunca roteado, entao nenhum servidor responde.
const UNREACHABLE_SERVER: &str = "192.0.2.1";

const CACHED_EXCHANGE: &str = "mx.cache.test";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Executa o binario com um cache isolado, para que o resultado nao dependa de
/// execucoes anteriores nem contamine o cache do usuario.
fn run_client(args: &[&str]) -> Output {
    run_client_with_cache(args, None)
}

/// Como `run_client`, mas grava `seed` no arquivo de cache antes de executar.
fn run_client_with_cache(args: &[&str], seed: Option<&str>) -> Output {
    let cache: PathBuf = std::env::temp_dir().join(format!(
        "dns-client-it-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if let Some(contents) = seed {
        std::fs::write(&cache, contents).expect("falha ao gravar o cache de teste");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_my-client"))
        .args(args)
        .env("DNS_CLIENT_CACHE", &cache)
        .output()
        .expect("falha ao executar o binario");
    let _ = std::fs::remove_file(&cache);
    output
}

/// Arquivo de cache com uma entrada MX de `unb.br` que nunca expira, no
/// formato gravado por `DnsCache` (dominio e resposta em hexadecimal).
fn cache_with_unb_mx() -> String {
    let hex = |text: &str| text.bytes().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "dns-cache-v1\n{}\t15\t{}\t{}\n",
        u64::MAX,
        hex("unb.br"),
        hex(CACHED_EXCHANGE)
    )
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
#[ignore = "requer rede"]
fn mx_record_found() {
    let output = run_client(&["unb.br", PUBLIC_RESOLVER]);
    let out = stdout(&output);

    assert!(output.status.success(), "stdout: {out}");
    assert!(out.starts_with("unb.br <> "), "saida inesperada: {out}");
    assert!(
        output.stderr.is_empty(),
        "stderr deveria estar vazio sem -v: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requer rede"]
fn a_record_found() {
    let output = run_client(&["unb.br", PUBLIC_RESOLVER, "--type", "A"]);
    let out = stdout(&output);

    assert!(output.status.success(), "stdout: {out}");
    assert!(
        out.lines().any(|line| line.starts_with("unb.br A ")),
        "stdout: {out}"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requer rede"]
fn nxdomain() {
    let output = run_client(&["imagdaskdasdasj.br", PUBLIC_RESOLVER]);

    assert!(!output.status.success());
    assert_eq!(
        stdout(&output),
        "Dominio imagdaskdasdasj.br nao encontrado\n"
    );
}

#[test]
#[ignore = "requer rede"]
fn domain_without_mx() {
    // fga.unb.br existe mas nao publica MX proprio; e o caso usado no mock local.
    let output = run_client(&["fga.unb.br", PUBLIC_RESOLVER]);

    assert!(!output.status.success());
    assert_eq!(
        stdout(&output),
        "Dominio fga.unb.br nao possui entrada MX\n"
    );
}

#[test]
#[ignore = "requer rede"]
fn server_does_not_answer() {
    let output = run_client(&["unb.br", UNREACHABLE_SERVER]);

    assert!(!output.status.success());
    assert_eq!(
        stdout(&output),
        "Nao foi possível coletar entrada MX para unb.br\n"
    );
}

// Regressao: o exemplo 4 do enunciado, executado depois do exemplo 1, devolvia
// a resposta guardada em vez de consultar o servidor informado.
#[test]
#[ignore = "requer rede"]
fn cache_is_not_used_without_the_cache_flag() {
    let seed = cache_with_unb_mx();
    let output = run_client_with_cache(&["unb.br", UNREACHABLE_SERVER], Some(&seed));

    assert!(!output.status.success());
    assert_eq!(
        stdout(&output),
        "Nao foi possível coletar entrada MX para unb.br\n"
    );
}

// Nao depende de rede: a resposta vem do arquivo de cache.
#[test]
fn cache_flag_reuses_a_stored_answer() {
    let seed = cache_with_unb_mx();
    let output = run_client_with_cache(&["unb.br", UNREACHABLE_SERVER, "--cache"], Some(&seed));

    assert!(output.status.success());
    assert_eq!(stdout(&output), format!("unb.br <> {CACHED_EXCHANGE}\n"));
}

#[test]
#[ignore = "requer rede"]
fn verbose_flag_enables_debug_logs() {
    let output = run_client(&["unb.br", PUBLIC_RESOLVER, "-v"]);
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(err.contains("[debug] tentativa 1/3"), "stderr: {err}");
}
