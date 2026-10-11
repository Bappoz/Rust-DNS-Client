mod dns;

use std::env;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use dns::cache::{DnsCache, unix_time_now};
use dns::message::{Header, Question, RecordType, parse_answers};
use dns::txid::Rng;

struct Args {
    domain: String,
    server_ip: String,
    verbose: bool,
    backoff: bool,
    record_type: RecordType,
}

// Logs de diagnostico so aparecem com -v/--verbose; erros reais usam eprintln! direto.
macro_rules! debug_log {
    ($args:expr, $($arg:tt)*) => {
        if $args.verbose {
            eprintln!($($arg)*);
        }
    };
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
    let mut argv = env::args();
    let prog = argv.next().unwrap_or_else(|| "my-client".to_string());
    parse_args_from(prog, argv)
}

fn parse_args_from(prog: String, argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let usage = format!(
        "uso: {prog} <dominio> <ip_servidor_dns> [-v|--verbose] [--backoff] [--type <A|AAAA|CNAME|NS|TXT|MX>]"
    );
    let mut verbose = false;
    let mut backoff = false;
    let mut record_type = RecordType::MX;
    let mut positional = Vec::new();
    let mut argv = argv.peekable();

    while let Some(argument) = argv.next() {
        match argument.as_str() {
            "-v" | "--verbose" => verbose = true,
            "--backoff" => backoff = true,
            "--type" => {
                let value = argv.next().ok_or_else(|| usage.clone())?;
                record_type = value.parse()?;
            }
            _ => positional.push(argument),
        }
    }

    match positional.as_slice() {
        [domain, server_ip] => Ok(Args {
            domain: domain.clone(),
            server_ip: server_ip.clone(),
            verbose,
            backoff,
            record_type,
        }),
        _ => Err(usage),
    }
}

fn retry_timeout(backoff: bool, attempt: usize) -> Duration {
    let seconds = match (backoff, attempt) {
        (false, _) => 2,
        (true, 1) => 1,
        (true, 2) => 2,
        (true, _) => 4,
    };
    Duration::from_secs(seconds)
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
    let question_bytes = if args.record_type == RecordType::MX {
        question.to_bytes()
    } else {
        question.to_bytes_for(args.record_type)
    };
    packet.extend_from_slice(&question_bytes);

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
            debug_log!(args, "[debug] cache DNS indisponivel: {error}");
            None
        }
    };
    if args.record_type == RecordType::MX
        && let Some(exchange) = cache
            .as_mut()
            .and_then(|cache| cache.get(&args.domain, args.record_type.code(), unix_time_now()))
    {
        debug_log!(args, "[debug] resposta obtida do cache DNS");
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

    debug_log!(
        args,
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
        debug_log!(args, "[debug] tentativa {attempt}/3");
        let timeout = retry_timeout(args.backoff, attempt);
        debug_log!(
            args,
            "[debug] timeout da tentativa {attempt}/3: {}ms",
            timeout.as_millis()
        );
        if let Err(e) = socket.send_to(&packet, server) {
            eprintln!("falha ao enviar consulta DNS: {e}");
            return ExitCode::FAILURE;
        }

        let deadline = Instant::now() + timeout;
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
                        debug_log!(
                            args,
                            "[debug] resposta UDP truncada; repetindo consulta via TCP"
                        );
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
                            debug_log!(args, "[debug] resposta DNS via TCP malformada: {error}");
                            return ExitCode::FAILURE;
                        }
                    };
                    if header.id != id || (header.flags & 0x8000) == 0 {
                        debug_log!(
                            args,
                            "[debug] resposta DNS via TCP nao corresponde a consulta"
                        );
                        return ExitCode::FAILURE;
                    }
                    if header.rcode() == 3 {
                        println!("Dominio {} nao encontrado", args.domain);
                        return ExitCode::FAILURE;
                    }
                    if header.rcode() != 0 {
                        continue;
                    }

                    match parse_answers(&response_packet, &header, args.record_type) {
                        Ok(answers) if answers.is_empty() => {
                            println!(
                                "Dominio {} nao possui entrada {}",
                                args.domain,
                                args.record_type.label()
                            );
                            return ExitCode::FAILURE;
                        }
                        Ok(answers) => {
                            if args.record_type == RecordType::MX {
                                let answer = &answers[0];
                                if let Some(cache) = cache.as_mut()
                                    && let Err(error) = cache.insert(
                                        &args.domain,
                                        args.record_type.code(),
                                        answer.value.clone(),
                                        answer.ttl,
                                        unix_time_now(),
                                    )
                                {
                                    debug_log!(
                                        args,
                                        "[debug] nao foi possivel atualizar o cache DNS: {error}"
                                    );
                                }
                                println!("{} <> {}", args.domain, answer.value);
                            } else {
                                for answer in answers {
                                    println!(
                                        "{} {} {}",
                                        args.domain,
                                        args.record_type.label(),
                                        answer.value
                                    );
                                }
                            }
                            return ExitCode::SUCCESS;
                        }
                        Err(error) => {
                            debug_log!(args, "[debug] resposta DNS malformada: {error}");
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
    fn retry_timeout_uses_fixed_default_and_optional_backoff() {
        let fixed_timeout = Duration::from_secs(2);
        for attempt in 1..=3 {
            assert_eq!(retry_timeout(false, attempt), fixed_timeout);
        }

        assert_eq!(retry_timeout(true, 1), Duration::from_secs(1));
        assert_eq!(retry_timeout(true, 2), Duration::from_secs(2));
        assert_eq!(retry_timeout(true, 3), Duration::from_secs(4));
    }

    #[test]
    fn backoff_flag_is_optional_and_accepted_in_any_position() {
        let default_args = parse_args_from(
            "my-client".into(),
            vec!["unb.br".into(), "8.8.8.8".into()].into_iter(),
        )
        .unwrap();
        assert!(!default_args.backoff);

        for arguments in [
            vec!["--backoff".into(), "unb.br".into(), "8.8.8.8".into()],
            vec!["unb.br".into(), "--backoff".into(), "8.8.8.8".into()],
            vec!["unb.br".into(), "8.8.8.8".into(), "--backoff".into()],
        ] {
            let args = parse_args_from("my-client".into(), arguments.into_iter()).unwrap();
            assert!(args.backoff);
        }
    }

    #[test]
    fn record_type_flag_defaults_to_mx_and_accepts_supported_types() {
        let default_args = parse_args_from(
            "my-client".into(),
            vec!["unb.br".into(), "8.8.8.8".into()].into_iter(),
        )
        .unwrap();
        assert_eq!(default_args.record_type, RecordType::MX);

        for (label, expected_type) in [
            ("A", RecordType::A),
            ("AAAA", RecordType::Aaaa),
            ("CNAME", RecordType::Cname),
            ("NS", RecordType::NS),
            ("TXT", RecordType::Txt),
            ("MX", RecordType::MX),
        ] {
            let args = parse_args_from(
                "my-client".into(),
                vec![
                    "unb.br".into(),
                    "8.8.8.8".into(),
                    "--type".into(),
                    label.into(),
                ]
                .into_iter(),
            )
            .unwrap();
            assert_eq!(args.record_type, expected_type);
        }

        assert!(
            parse_args_from(
                "my-client".into(),
                vec![
                    "unb.br".into(),
                    "8.8.8.8".into(),
                    "--type".into(),
                    "PTR".into()
                ]
                .into_iter(),
            )
            .is_err()
        );
    }

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
