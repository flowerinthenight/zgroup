#!/bin/bash
mkdir /opt/zgroup/ && cd /opt/zgroup/
wget https://github.com/flowerinthenight/zgroup/releases/download/v0.3.1/zgroup-v0.3.1-x86_64-linux.tar.gz
tar -xzvf zgroup-v0.3.1-x86_64-linux.tar.gz
# ZGROUP_JOIN_PREFIX=0b9303ad-1beb-483f-abb5-bc58e0214531 INTERNAL_IP=$(curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip) ./zgroup group1 ${INTERNAL_IP}:8080 2>&1 | logger &
