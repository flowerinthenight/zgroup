[![main](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml)

**zgroup** is a library that can manage cluster membership and member failure detection. It is based on the [SWIM Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf), specifically the **SWIM+Inf.+Susp.** variant of the gossip protocol.

A [sample binary](./src/main.zig) is provided to show a way to use the library. There's two ways to run the sample: **a)** manually specifying the join address, and **b)** using an external service to get the join address.

To run locally using **a)**, try:

```sh
# Build the sample binary:
$ zig build --summary all

# Run the 1st process. The expected args look like:
#
#   ./zgroup groupname member_ip:port [join_ip:port]
#
# Run the first process (join to self).
$ ./zig-out/bin/zgroup group1 0.0.0.0:8080 0.0.0.0:8080

# Then you can run additional instances.
# Join through the 1st process/node (different terminal):
$ ./zig-out/bin/zgroup group1 0.0.0.0:8081 0.0.0.0:8080

# Join through the 2nd process/node (different terminal):
$ ./zig-out/bin/zgroup group1 0.0.0.0:8082 0.0.0.0:8081

# Join through the 1st process/node (different terminal):
$ ./zig-out/bin/zgroup group1 0.0.0.0:8083 0.0.0.0:8080

# and so on...
```

To run locally using **b)**, the sample binary uses a free service, [https://keyvalue.immanuel.co/](https://keyvalue.immanuel.co/), as the discovery service for the join address.

The implementation is still a work-in-progress at this point, especially the infection-style member/state info dissemination, as well as the API to get the latest members in the cluster.
