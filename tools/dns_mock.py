"""Servidor UDP DNS minimo para testar o cliente localmente.

Responde com MX para ``unb.br``, sem MX para ``fga.unb.br`` e NXDOMAIN para
o dominio inexistente usado no enunciado. O Transaction ID e a secao Question
da consulta recebida sao reutilizados na resposta para exercitar o cliente.
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


def query_name(question: bytes) -> str | None:
    """Decodifica o QNAME sem compressao enviado pelo cliente."""
    labels = []
    cursor = 0
    while cursor < len(question):
        label_length = question[cursor]
        cursor += 1
        if label_length == 0:
            return ".".join(labels)
        label_end = cursor + label_length
        if label_end > len(question):
            return None
        labels.append(question[cursor:label_end].decode("ascii"))
        cursor = label_end
    return None


def make_response(request: bytes) -> tuple[bytes, str] | None:
    if len(request) < 12:
        return None

    transaction_id = request[:2]
    question_count = request[4:6]
    question = request[12:]
    domain = query_name(question)
    if domain is None:
        return None

    flags = b"\x81\x80"  # Resposta padrao, recursion available, NOERROR.
    answer_count = b"\x00\x01"
    answer = MX_ANSWER
    if domain == "imagdaskdasdasj.br":
        flags = b"\x81\x83"  # NXDOMAIN.
        answer_count = b"\x00\x00"
        answer = b""
    elif domain == "fga.unb.br":
        answer_count = b"\x00\x00"  # NOERROR, sem MX.
        answer = b""

    response = (
        transaction_id
        + flags
        + question_count
        + answer_count
        + b"\x00\x00\x00\x00"  # NSCOUNT e ARCOUNT = 0
        + question
        + answer
    )
    return response, domain


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        print(f"Mock DNS escutando em udp://{HOST}:{PORT}")
        while True:
            request, client = sock.recvfrom(512)
            result = make_response(request)
            if result is None:
                continue
            response, domain = result
            print(f"Consulta de {client} para {domain}")
            sock.sendto(response, client)


if __name__ == "__main__":
    main()
