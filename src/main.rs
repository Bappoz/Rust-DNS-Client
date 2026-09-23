mod dns;

use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

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

    let server = match format!("{}:53", args.server_ip).parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("ip do servidor DNS invalido: {e}");
            return ExitCode::FAILURE;
        }
    };

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("nao foi possivel criar o socket UDP: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(2))) {
        eprintln!("nao foi possivel configurar o timeout de leitura: {e}");
        return ExitCode::FAILURE;
    }

    eprintln!(
        "[debug] servidor={} txid=0x{id:04x} pacote ({} bytes): {}",
        args.server_ip,
        packet.len(),
        packet
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut response = [0u8; 512];
    // Reenvia o mesmo pacote e TXID: simplifica a correlacao e segue o padrao
    // comum de resolvers; um novo TXID evitaria aceitar respostas atrasadas.
    for attempt in 1..=3 {
        if let Err(e) = socket.send_to(&packet, server) {
            eprintln!("falha ao enviar consulta DNS: {e}");
            return ExitCode::FAILURE;
        }

        match socket.recv_from(&mut response) {
            Ok((size, source)) => {
                if source != server
                    || size < 12
                    || u16::from_be_bytes([response[0], response[1]]) != id
                {
                    continue;
                }
                eprintln!(
                    "[debug] resposta recebida na tentativa {attempt} de {source} ({size} bytes)"
                );
                return ExitCode::SUCCESS;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => {
                eprintln!("falha ao receber resposta DNS: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    println!(
        "Nao foi possível coletar entrada MX para {}",
        args.domain
    );
    ExitCode::FAILURE
}
