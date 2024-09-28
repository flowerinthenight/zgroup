**NOTE**: Still in alpha stage. APIs may change.

---

[![main](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml)
[![Docker Repository on Quay](https://quay.io/repository/flowerinthenight/zgroup/status "Docker Repository on Quay")](https://quay.io/repository/flowerinthenight/zgroup)

## Overview

**zgroup** is a [Zig](https://ziglang.org/) library that can manage cluster membership and member failure detection. It uses a combination of [SWIM Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf)'s gossip-style information dissemination, and [Raft](https://raft.github.io/raft.pdf)'s leader election algorithm (minus the log management) to track cluster changes.

### On payload size

One of zgroup's main goal is to be able to track clusters with sizes that can change dynamically overtime (e.g. [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/), [GCP Instance Groups](https://cloud.google.com/compute/docs/instance-groups), [AWS Autoscaling Groups](https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-groups.html), etc.) with minimal dependencies and network load. My previous related works usually rely on some external service (see [spindle](https://github.com/flowerinthenight/spindle), [hedge](https://github.com/flowerinthenight/hedge)), using traditional heartbeating, to achieve this. This heartbeating technique usually suffers from increasing payload sizes (proportional to cluster sizes) as clusters get bigger. But I wanted a system that doesn't suffer from that side effect. Enter [SWIM](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf)'s infection-style information dissemination. It can use a constant payload size regardless of the cluster size. SWIM uses a combination of `PING`s, `INDIRECT-PING`s, and `ACK`s to detect member failures while piggybacking on these same messages to propagate membership updates (gossip protocol). At the moment, zgroup only uses SWIM's direct probing protocol; it doesn't fully implement the Suspicion sub-protocol (yet).

### On leader election

I also wanted some sort of leader election capability without depending on an external lock service. At the moment, `zgroup` uses [Raft](https://raft.github.io/raft.pdf)'s election algorithm subprotocol (without the log management) to achieve this. I should note that Raft's leader election algorithm rely on stable membership for it work properly, so zgroup's leader election is a best-effort basis only; split-brain can still happen while the cluster size is changing. Additional code guards are added to minimize split-brain scenarios but it's not completely eliminated. In my use-case (and testing), gradual cluster size changes are mostly stable, while huge size deltas are not. For example, a big, sudden jump from three nodes (zgroup's minimum size) to, say, a hundred, due to autoscaling, would cause split-brain.

### Join address

To be done.

## Sample binary

A [sample](./src/main.zig) binary is provided to show a way to use the library. There are two ways to run the sample: **a)** specifying the join address manually, and **b)** using an external service to get the join address.

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

To run locally using **b)**, the sample binary uses a free service, [https://keyvalue.immanuel.co/](https://keyvalue.immanuel.co/), as a store for the join address. The library provides a simple, best-effort-basis leader election mechanism for this purpose by providing a callback with a join address information that you can store somewhere.

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
const members = try fleet.getMembers(gpa.allocator());
defer members.deinit();

for (members.items, 0..) |v, i| {
    defer gpa.allocator().free(v);
    log.info("member[{d}]: {s}", .{ i, v });
}
```

The tricky part of using **zgroup** is configuring the timeouts to optimize state dissemination and convergence. The current implementation was only tested within a local network.
