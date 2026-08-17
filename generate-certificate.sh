#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./generate-certificate.sh <type> [options]

Types:
  server    TLS certificate the SGP listener presents and clients pin
              -> cert.pem, key.pem            (SGP_CERT_PATH, SGP_KEY_PATH)
  ca        registration CA that authorizes device enrolment
              -> reg-ca.pem, reg-ca-key.pem   (SGP_REG_CA_PATH is reg-ca.pem)
  client    registration certificate for one operator, signed by the CA
              -> NAME.pem, NAME-key.pem, NAME-identity.pem
              (NAME-identity.pem is cert+key concatenated — import that
               into the iOS client's registration cert picker)

Options:
  -n, --name NAME   server hostname, or client CN
                    (server default: $SGP_SERVER_ADDRESS, else localhost)
  -d, --days N      validity (default: 3650 for ca, 825 server, 365 client)
  -o, --out DIR     output directory (default: .)
      --ca-dir DIR  where reg-ca.pem and reg-ca-key.pem live (default: .)
      --force       overwrite existing files
  -h, --help

Examples:
  ./generate-certificate.sh server --name sgn.example.com
  ./generate-certificate.sh ca --out ~/.skyglow
  ./generate-certificate.sh client --name alice --ca-dir ~/.skyglow
EOF
}

TYPE="${1:-}"
[[ -z "$TYPE" || "$TYPE" == "-h" || "$TYPE" == "--help" ]] && { usage; exit 0; }
shift

NAME=""
DAYS=""
OUT="."
CA_DIR="."
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--name)   NAME="$2"; shift 2 ;;
        -d|--days)   DAYS="$2"; shift 2 ;;
        -o|--out)    OUT="$2"; shift 2 ;;
        --ca-dir)    CA_DIR="$2"; shift 2 ;;
        --force)     FORCE=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

mkdir -p "$OUT"

guard() {
    for f in "$@"; do
        if [[ -e "$f" && $FORCE -eq 0 ]]; then
            echo "Refusing to overwrite $f (pass --force)" >&2
            exit 1
        fi
    done
}

case "$TYPE" in

server)
    NAME="${NAME:-${SGP_SERVER_ADDRESS:-localhost}}"
    DAYS="${DAYS:-825}"
    CERT="$OUT/cert.pem"
    KEY="$OUT/key.pem"
    guard "$CERT" "$KEY"

    SAN="DNS:$NAME"
    [[ "$NAME" != "localhost" ]] && SAN="$SAN,DNS:localhost,IP:127.0.0.1"

    openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
        -keyout "$KEY" \
        -out    "$CERT" \
        -days   "$DAYS" \
        -subj   "/CN=$NAME" \
        -addext "subjectAltName=$SAN" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth"

    chmod 600 "$KEY"
    echo
    echo "Server certificate created (valid $DAYS days):"
    echo "  SGP_CERT_PATH=$CERT"
    echo "  SGP_KEY_PATH=$KEY"
    openssl x509 -in "$CERT" -noout -subject -enddate | sed 's/^/  /'
    ;;

ca)
    DAYS="${DAYS:-3650}"
    CA_CERT="$OUT/reg-ca.pem"
    CA_KEY="$OUT/reg-ca-key.pem"
    guard "$CA_CERT" "$CA_KEY"

    openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
        -keyout "$CA_KEY" \
        -out    "$CA_CERT" \
        -days   "$DAYS" \
        -subj   "/CN=${NAME:-Skyglow Registration CA}" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign"

    chmod 600 "$CA_KEY"
    echo
    echo "Registration CA created (valid $DAYS days):"
    echo "  SGP_REG_CA_PATH=$CA_CERT"
    echo "  CA private key : $CA_KEY  (keep offline; the server never reads it)"
    ;;

client)
    [[ -n "$NAME" ]] || { echo "client requires --name" >&2; exit 1; }
    DAYS="${DAYS:-365}"
    CA_CERT="$CA_DIR/reg-ca.pem"
    CA_KEY="$CA_DIR/reg-ca-key.pem"
    [[ -f "$CA_CERT" && -f "$CA_KEY" ]] || {
        echo "CA not found in $CA_DIR — run: $0 ca --out $CA_DIR" >&2; exit 1; }

    CERT="$OUT/$NAME.pem"
    KEY="$OUT/$NAME-key.pem"
    CSR="$OUT/$NAME.csr"
    IDENTITY="$OUT/$NAME-identity.pem"
    guard "$CERT" "$KEY" "$IDENTITY"

    openssl req -newkey rsa:2048 -sha256 -nodes \
        -keyout "$KEY" \
        -out    "$CSR" \
        -subj   "/CN=$NAME"

    openssl x509 -req -sha256 \
        -in      "$CSR" \
        -CA      "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out     "$CERT" \
        -days    "$DAYS" \
        -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")

    rm -f "$CSR"
    chmod 600 "$KEY"

    cat "$CERT" "$KEY" > "$IDENTITY"
    chmod 600 "$IDENTITY"

    echo
    echo "Registration certificate issued (valid $DAYS days):"
    echo "  certificate : $CERT"
    echo "  private key : $KEY"
    echo "  identity    : $IDENTITY  (import this into the client)"
    openssl x509 -in "$CERT" -noout -subject -enddate | sed 's/^/  /'
    ;;

*)
    echo "Unknown type: $TYPE" >&2
    usage >&2
    exit 1
    ;;
esac
