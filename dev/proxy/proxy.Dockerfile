# An HTTP proxy that needs a user name and a password, and logs each request.
FROM alpine:3.20
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
# tinyproxy reads no environment variables, so the start command adds the
# credentials to the configuration.
CMD ["sh", "-c", "echo \"BasicAuth $PROXY_USER $PROXY_PASSWORD\" >> /etc/tinyproxy/tinyproxy.conf && exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf"]
