"""Servidor UDP DNS minimo para testar o cliente localmente.

Responde a qualquer consulta com um registro MX comprimido para
``mail.unb.br``. O Transaction ID e a secao Question da consulta recebida sao
reutilizados na resposta para exercitar a validacao do cliente.
"""

import socket


HOST = "127.0.0.1"
PORT = 53

# NAME aponta para o QNAME da Question (offset 12). O RDATA MX contem:
# PREFERENCE = 10; EXCHANGE = mail + ponteiro para unb.br.
MX_ANSWER = (
    b"\xc0\x0c"  # NAME: ponteiro para QNAME
    b"\x00\x0f"  # TYPE: MX
    b"\x00\x01"  # CLASS: IN
    b"\x00\x00\x0e\x10"  # TTL: 3600
    b"\x00\x09"  # RDLENGTH: 9 bytes
    b"\x00\x0a"  # PREFERENCE: 10
    b"\x04mail\xc0\x0c"  # EXCHANGE: mail.unb.br
)


def make_response(request: bytes) -> bytes | None:
    if len(request) < 12:
        return None

    transaction_id = request[:2]
    question_count = request[4:6]
    question = request[12:]
    return (
        transaction_id
        + b"\x81\x80"  # Resposta padrao, recursion available, NOERROR.
        + question_count
        + b"\x00\x01"  # ANCOUNT = 1
        + b"\x00\x00\x00\x00"  # NSCOUNT e ARCOUNT = 0
        + question
        + MX_ANSWER
    )


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        print(f"Mock DNS escutando em udp://{HOST}:{PORT}")
        while True:
            request, client = sock.recvfrom(512)
            response = make_response(request)
            if response is None:
                continue
            print(f"Consulta de {client}; respondendo com MX mail.unb.br")
            sock.sendto(response, client)


if __name__ == "__main__":
    main()
