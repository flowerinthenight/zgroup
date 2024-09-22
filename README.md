[![main](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml)

**zgroup** is a [Zig](https://ziglang.org/) library that can manage cluster membership and member failure detection. It is based on the [SWIM Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf), specifically the **SWIM+Inf.+Susp.** variant of the gossip protocol.

A [sample](./src/main.zig) binary is provided to show a way to use the library. There are two ways to run the sample: **a)** manually specifying the join address, and **b)** using an external service to get the join address.

To run locally using **a)**, try something like:

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

To run locally using **b)**, the sample binary uses a free service, [https://keyvalue.immanuel.co/](https://keyvalue.immanuel.co/), as a store for the join address. The library provides a simple, best-effort-basis leader election mechanism for this purpose by providing a callback with a join address information that can be stored on an external service.

```sh
# Build the sample binary:
$ zig build --summary all

# The sample code embeds the API key, with the group name as key.
# I suggest you change that.

# Run the 1st process. The expected args look like:
#
#   ./zgroup groupname member_ip:port
#

# Run the first process:
$ ./zig-out/bin/zgroup group1 0.0.0.0:8080

# Add a second node (different terminal):
$ ./zig-out/bin/zgroup group1 0.0.0.0:8081

# Add a third node (different terminal):
$ ./zig-out/bin/zgroup group1 0.0.0.0:8082

# Add a fourth node (different terminal):
$ ./zig-out/bin/zgroup group1 0.0.0.0:8083

# and so on...
```

To get the current members of the group, you can try something like:

```zig
const members = try fleet.memberNames(gpa.allocator());
defer members.deinit();

for (members.items, 0..) |v, i| {
    defer gpa.allocator().free(v);
    log.info("member[{d}]: {s}", .{ i, v });
}
```

The tricky part of using **zgroup** is configuring the timeouts to optimize state dissemination and member convergence. The current implementation was only tested within a local network.
