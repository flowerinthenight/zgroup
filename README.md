[![main](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml)

**zgroup** is a library that can manage cluster membership and member failure detection. It is based on the [SWIM Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf), specifically the **SWIM+Inf.+Susp.** variant of the gossip protocol. Linux-only for now.

To run locally:

```sh
# Build the sample binary:
$ zig build --summary all

# Run the 1st process. The expected args look like:
#
#   ./zgroup name_in_uuid member_ip:port join_ip:port
#
# Run the first process without the join args.
$ ./zig-out/bin/zgroup 0xf47ac10b58cc4372a5670e02b2c3d479 0.0.0.0:8080 :

# Then you can run multiple instances, specifying the join address.
# Join through the 1st process/node (different terminal):
$ ./zig-out/bin/zgroup 0xf47ac10b58cc4372a5670e02b2c3d479 0.0.0.0:8081 0.0.0.0:8080

# Join through the 2nd process/node (different terminal):
$ ./zig-out/bin/zgroup 0xf47ac10b58cc4372a5670e02b2c3d479 0.0.0.0:8082 0.0.0.0:8081

# Join through the 1st process/node (different terminal):
$ ./zig-out/bin/zgroup 0xf47ac10b58cc4372a5670e02b2c3d479 0.0.0.0:8083 0.0.0.0:8080

# and so on...
```

The implementation is still a work-in-progress at this point, especially the infection-style member/state info dissemination.
