#!/bin/bash
mkdir /opt/zgroup/ && cd /opt/zgroup/
wget https://github.com/flowerinthenight/zgroup/releases/download/v0.3.2/zgroup-v0.3.2-x86_64-linux.tar.gz
tar -xzvf zgroup-v0.3.2-x86_64-linux.tar.gz
# METADATA_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# INTERNAL_IP=$(curl -H "X-aws-ec2-metadata-token: $METADATA_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
# ZGROUP_JOIN_PREFIX=0b9303ad-1beb-483f-abb5-bc58e0214531 ./zgroup group1 ${INTERNAL_IP}:8080 2>&1 | logger &
