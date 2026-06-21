#!/usr/bin/env python3
"""Live smoke test: drive the assinador HTTP microservice from Python.

Generates a minimal valid PDF, then runs the full VIDaaS flow against a running
assinador-server:  start -> poll (until approved on phone) -> exchange -> sign.

Usage:
    python3 scripts/smoke_test.py <CPF> [--base http://localhost:8080] [--out signed.pdf]
"""

import argparse
import base64
import sys
import time

import requests


def check(r: requests.Response) -> requests.Response:
    """Raise for status, but surface the server's JSON error detail first."""
    if not r.ok:
        print(f"      <- HTTP {r.status_code}: {r.text}", file=sys.stderr)
    r.raise_for_status()
    return r


def build_minimal_pdf(text: str) -> bytes:
    """Assemble a tiny, valid single-page PDF with a correct xref table."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 320 120] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\nBT /F1 16 Tf 24 60 Td (%s) Tj ET\nendstream"
        % (len(text) + 22, text.encode("latin-1")),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n" % i + body + b"\nendobj\n"

    xref_pos = len(pdf)
    pdf += b"xref\n0 %d\n" % (len(objects) + 1)
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += b"%010d 00000 n \n" % off
    pdf += (
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF"
        % (len(objects) + 1, xref_pos)
    )
    return bytes(pdf)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cpf", help="CPF enrolled in VIDaaS (digits only)")
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--out", default="signed.pdf")
    ap.add_argument("--timeout", type=int, default=180, help="seconds to wait for approval")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    pdf = build_minimal_pdf("Teste de assinatura - assinador")
    print(f"PDF de teste: {len(pdf)} bytes")

    # 1. start push authorization (triggers the prompt on the phone)
    print("\n[1/4] /v1/auth/start -> disparando push no celular...")
    r = check(requests.post(f"{base}/v1/auth/start", json={"cpf": args.cpf}, timeout=30))
    start = r.json()
    code, verifier = start["code"], start["verifier"]
    print(f"      code={code[:12]}...  (aprove a notificacao no app VIDaaS)")

    # 2. poll until approved
    print("[2/4] /v1/auth/poll -> aguardando aprovacao...")
    deadline = time.time() + args.timeout
    while True:
        r = check(requests.get(f"{base}/v1/auth/poll", params={"code": code}, timeout=30))
        body = r.json()
        if body["status"] == "approved":
            authorization_token = body["authorization_token"]
            print("      aprovado!")
            break
        if time.time() > deadline:
            print("      TIMEOUT aguardando aprovacao.", file=sys.stderr)
            return 2
        print("      pending... (nova tentativa em 3s)")
        time.sleep(3)

    # 3. exchange code+verifier for the access token
    print("[3/4] /v1/auth/exchange -> obtendo access token...")
    r = requests.post(
        f"{base}/v1/auth/exchange",
        json={"authorization_token": authorization_token, "verifier": verifier},
        timeout=30,
    )
    check(r)
    token = r.json()["access_token"]
    print(f"      token obtido (expires_in={r.json()['expires_in']}s)")

    # 4. sign the PDF
    print("[4/4] /v1/sign -> assinando o PDF...")
    pdf_b64 = base64.b64encode(pdf).decode()
    r = requests.post(
        f"{base}/v1/sign",
        json={
            "access_token": token,
            "documents": [{"id": "d1", "alias": "teste", "pdf_base64": pdf_b64}],
        },
        timeout=60,
    )
    check(r)
    signed_b64 = r.json()["signed"][0]["pdf_base64"]
    signed = base64.b64decode(signed_b64)

    with open(args.out, "wb") as f:
        f.write(signed)
    print(f"\nOK! PDF assinado salvo em {args.out} ({len(signed)} bytes, "
          f"header={signed[:5]!r}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
