#!/bin/sh
# Assign an IP address to local loopback 
ip addr add 127.0.0.1/32 dev lo

ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1   dynamodb.us-west-2.amazonaws.com" >> /etc/hosts

# npm start --prefix /app &
/app/actix & socat VSOCK-LISTEN:8001,fork,reuseaddr TCP:127.0.0.1:3000 & socat TCP-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:3:8002
