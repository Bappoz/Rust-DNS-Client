mod dns;

use std::env;
use std::process::ExitCode;

use dns::message::{Header, Question};
use dns::txid::Rng;

struct Args {
    domain: String,
    server_ip: String,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = env::args().collect();
    match argv.as_slice() {
        [_prog, domain, server_ip] => Ok(Args {
            domain: domain.clone(),
            server_ip: server_ip.clone(),
        }),
        [prog, ..] => Err(format!("uso: {prog} <dominio> <ip_servidor_dns>")),
        [] => unreachable!("argv sempre tem ao menos o nome do programa!"),
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    let question = match Question::new(&args.domain) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("dominio invalido: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut rng = Rng::seeded_from_clock();
    let id = rng.next_u16();
    let header = Header::new_query(id);

    let mut packet = header.to_bytes().to_vec();
    packet.extend_from_slice(&question.to_bytes());

    eprintln!(
        "[debug] servidor={} txid=0x{id:04x} pacode ({} bytes): {}",
        args.server_ip,
        packet.len(),
        packet
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    ExitCode::SUCCESS
}
