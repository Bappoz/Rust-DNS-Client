mod dns;

use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use dns::cache::{DnsCache, unix_time_now};
use dns::message::QTYPE_MX;
use dns::message::{Header, Question, parse_mx_answer};
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

    let mut cache = match DnsCache::open_default() {
        Ok(cache) => cache,
        Err(error) => {
            eprintln!("[debug] cache DNS indisponivel: {error}");
            None
        }
    };
    if let Some(exchange) = cache
        .as_mut()
        .and_then(|cache| cache.get(&args.domain, QTYPE_MX, unix_time_now()))
    {
        eprintln!("[debug] resposta obtida do cache DNS");
        println!("{} <> {exchange}", args.domain);
        return ExitCode::SUCCESS;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("nao foi possivel criar o socket UDP: {e}");
            return ExitCode::FAILURE;
        }
    };

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
        eprintln!("[debug] tentativa {attempt}/3");
        if let Err(e) = socket.send_to(&packet, server) {
            eprintln!("falha ao enviar consulta DNS: {e}");
            return ExitCode::FAILURE;
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Err(e) = socket.set_read_timeout(Some(remaining)) {
                eprintln!("nao foi possivel configurar o timeout de leitura: {e}");
                return ExitCode::FAILURE;
            }

            match socket.recv_from(&mut response) {
                Ok((size, source)) => {
                    if source != server || size < 12 {
                        continue;
                    }

                    let header = match Header::from_bytes(&response[..size]) {
                        Ok(header) => header,
                        Err(_) => continue,
                    };
                    if header.id != id || (header.flags & 0x8000) == 0 {
                        continue;
                    }

                    if header.rcode() == 3 {
                        println!("Dominio {} nao encontrado", args.domain);
                        return ExitCode::FAILURE;
                    }
                    if header.rcode() != 0 {
                        continue;
                    }

                    match parse_mx_answer(&response[..size], &header) {
                        Ok(Some(answer)) => {
                            if let Some(cache) = cache.as_mut()
                                && let Err(error) = cache.insert(
                                    &args.domain,
                                    QTYPE_MX,
                                    answer.exchange.clone(),
                                    answer.ttl,
                                    unix_time_now(),
                                )
                            {
                                eprintln!(
                                    "[debug] nao foi possivel atualizar o cache DNS: {error}"
                                );
                            }
                            println!("{} <> {}", args.domain, answer.exchange);
                            return ExitCode::SUCCESS;
                        }
                        Ok(None) => {
                            println!("Dominio {} nao possui entrada MX", args.domain);
                            return ExitCode::FAILURE;
                        }
                        Err(error) => {
                            eprintln!("[debug] resposta DNS malformada: {error}");
                            continue;
                        }
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) => {
                    eprintln!("falha ao receber resposta DNS: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    println!("Nao foi possível coletar entrada MX para {}", args.domain);
    ExitCode::FAILURE
}
