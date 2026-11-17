# TLS in front of the Adversarial API on the host, as https://api.test:8443.
FROM alpine:3.20
RUN apk add --no-cache socat
CMD ["socat", "OPENSSL-LISTEN:8443,reuseaddr,fork,cert=/certs/api.pem,verify=0", "TCP:host.docker.internal:8080"]
