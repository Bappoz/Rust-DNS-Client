mod dns;

use std::env;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
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

fn query_over_tcp(server: SocketAddr, packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let length = u16::try_from(packet.len())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "consulta DNS excede 65535 bytes"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(packet)?;

    let mut length_bytes = [0u8; 2];
    stream.read_exact(&mut length_bytes)?;
    let response_length = u16::from_be_bytes(length_bytes) as usize;
    let mut response = vec![0u8; response_length];
    stream.read_exact(&mut response)?;
    Ok(response)
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

                    let response_packet = if header.is_truncated() {
                        eprintln!("[debug] resposta UDP truncada; repetindo consulta via TCP");
                        match query_over_tcp(server, &packet) {
                            Ok(response) => response,
                            Err(error) => {
                                eprintln!("falha na consulta DNS via TCP: {error}");
                                return ExitCode::FAILURE;
                            }
                        }
                    } else {
                        response[..size].to_vec()
                    };

                    let header = match Header::from_bytes(&response_packet) {
                        Ok(header) => header,
                        Err(error) => {
                            eprintln!("[debug] resposta DNS via TCP malformada: {error}");
                            return ExitCode::FAILURE;
                        }
                    };
                    if header.id != id || (header.flags & 0x8000) == 0 {
                        eprintln!("[debug] resposta DNS via TCP nao corresponde a consulta");
                        return ExitCode::FAILURE;
                    }
                    if header.rcode() == 3 {
                        println!("Dominio {} nao encontrado", args.domain);
                        return ExitCode::FAILURE;
                    }
                    if header.rcode() != 0 {
                        continue;
                    }

                    match parse_mx_answer(&response_packet, &header) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn tcp_query_uses_dns_length_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let request = vec![0x12, 0x34, 0x01, 0x00];
        let expected_response = vec![0x12, 0x34, 0x81, 0x80];
        let expected_request_on_server = request.clone();
        let response_from_server = expected_response.clone();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length_bytes = [0u8; 2];
            stream.read_exact(&mut length_bytes).unwrap();
            let request_length = u16::from_be_bytes(length_bytes) as usize;
            let mut received_request = vec![0u8; request_length];
            stream.read_exact(&mut received_request).unwrap();
            assert_eq!(received_request, expected_request_on_server);

            stream
                .write_all(&(response_from_server.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response_from_server).unwrap();
        });

        assert_eq!(query_over_tcp(server, &request).unwrap(), expected_response);
        server_thread.join().unwrap();
    }
}
