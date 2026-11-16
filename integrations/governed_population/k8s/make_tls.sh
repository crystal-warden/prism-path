#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# A local CA and the webhook's serving certificate, for the API server to reach the webhook over TLS.
#
#   sh make_tls.sh OUT [SERVICE] [NAMESPACE]
#
# Writes OUT/ca.key, OUT/ca.crt, OUT/tls.key, OUT/tls.crt (keys mode 0600). The serving certificate names
# the Service's in-cluster DNS names; PRISMPATH_TLS_EXTRA_SAN adds more (for a local test, e.g.
# "DNS:localhost,IP:127.0.0.1"). Nothing here is committed: OUT belongs under k8s/secrets/, which git ignores.
# The CA's certificate goes into the ValidatingWebhookConfiguration's caBundle; its key signs nothing else.
set -eu
out=${1:?usage: make_tls.sh OUT [SERVICE] [NAMESPACE]}
service=${2:-population-webhook}
namespace=${3:-prismpath-population-system}
days=${PRISMPATH_TLS_DAYS:-365}
san="DNS:$service.$namespace.svc,DNS:$service.$namespace.svc.cluster.local,DNS:$service.$namespace"
if [ -n "${PRISMPATH_TLS_EXTRA_SAN:-}" ]; then san="$san,$PRISMPATH_TLS_EXTRA_SAN"; fi

mkdir -p "$out"
for f in ca.key ca.crt tls.key tls.crt; do
  if [ -e "$out/$f" ]; then echo "make_tls.sh: $out/$f exists; refusing to replace it" >&2; exit 1; fi
done
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/ca.key"
openssl req -x509 -new -key "$out/ca.key" -sha256 -days "$days" -subj "/CN=prismpath population webhook CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$out/ca.crt"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/tls.key"
openssl req -new -key "$out/tls.key" -subj "/CN=$service.$namespace.svc" -out "$out/tls.csr"
cat > "$out/tls.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$san
EXT
openssl x509 -req -in "$out/tls.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" -CAcreateserial -sha256 \
  -days "$days" -extfile "$out/tls.ext" -out "$out/tls.crt"
rm -f "$out/tls.csr" "$out/tls.ext" "$out/ca.srl"
chmod 0644 "$out/ca.crt" "$out/tls.crt"
echo "make_tls.sh: wrote $out/ca.crt and $out/tls.crt for $service.$namespace.svc"
