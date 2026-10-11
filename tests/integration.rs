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

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Executa o binario com um cache isolado, para que o resultado nao dependa de
/// execucoes anteriores nem contamine o cache do usuario.
fn run_client(args: &[&str]) -> Output {
    let cache: PathBuf = std::env::temp_dir().join(format!(
        "dns-client-it-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_my-client"))
        .args(args)
        .env("DNS_CLIENT_CACHE", &cache)
        .output()
        .expect("falha ao executar o binario");
    let _ = std::fs::remove_file(&cache);
    output
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

#[test]
#[ignore = "requer rede"]
fn verbose_flag_enables_debug_logs() {
    let output = run_client(&["unb.br", PUBLIC_RESOLVER, "-v"]);
    let err = String::from_utf8_lossy(&output.stderr);

    assert!(err.contains("[debug] tentativa 1/3"), "stderr: {err}");
}
