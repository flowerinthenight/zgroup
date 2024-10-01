**NOTE**: Still in alpha stage. APIs may change.

---

[![main](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml/badge.svg)](https://github.com/flowerinthenight/zgroup/actions/workflows/main.yml)
[![Docker Repository on Quay](https://quay.io/repository/flowerinthenight/zgroup/status "Docker Repository on Quay")](https://quay.io/repository/flowerinthenight/zgroup)

## Overview

**zgroup** is a [Zig](https://ziglang.org/) library that can manage cluster membership and member failure detection. It uses a combination of [SWIM Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf)'s gossip-style information dissemination, and [Raft](https://raft.github.io/raft.pdf)'s leader election algorithm (minus the log management) to track cluster changes.

### On payload size

One of zgroup's main goal is to be able to track clusters with sizes that can change dynamically overtime (e.g. [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/), [GCP Instance Groups](https://cloud.google.com/compute/docs/instance-groups), [AWS Autoscaling Groups](https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-groups.html), etc.) with minimal dependencies and network load. All of my previous related works so far, depend on some external service (see [spindle](https://github.com/flowerinthenight/spindle), [hedge](https://github.com/flowerinthenight/hedge)), using traditional heartbeating, to achieve this. This heartbeating technique usually suffers from increasing payload sizes (proportional to cluster sizes) as clusters get bigger. But I wanted a system that doesn't suffer from that side effect. Enter [SWIM](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf)'s infection-style information dissemination. It can use a constant payload size regardless of the cluster size. SWIM uses a combination of `PING`s, `INDIRECT-PING`s, and `ACK`s to detect member failures while piggybacking on these same messages to propagate membership updates (gossip protocol). Currently, zgroup only uses SWIM's direct probing protocol; it doesn't fully implement the Suspicion sub-protocol (yet).

At the moment, zgroup uses a single, 64-byte payload for all its messages, including leader election (see below).

### On leader election

I also wanted some sort of leader election capability without depending on an external lock service. At the moment, zgroup uses [Raft](https://raft.github.io/raft.pdf)'s leader election algorithm sub-protocol (without the log management) to achieve this. I should note that Raft's leader election algorithm depends on stable membership for it work properly, so zgroup's leader election is a best-effort basis only; split-brain can still happen while the cluster size is still changing. Additional code guards are added to minimize split-brain in these scenarios but it's not completely eliminated. In my use-case (and testing), gradual cluster size changes are mostly stable, while sudden changes with huge size deltas are not. For example, a big, sudden jump from three nodes (zgroup's minimum size) to, say, a hundred, due to autoscaling, would cause a split-brain. Once the target size is achieved however, a single leader will always be elected.

A note on Raft's random timeout range during leader election: zgroup's leader tracks ping latency averages and attempts to adjust the timeout range accordingly to accomodate for cluster size changes overtime.

### Join address

For a node to join an existing cluster, it needs a joining address. While zgroup exposes a `join()` function for this, it also provides a callback mechanism, providing callers with a join address. This address can then be stored to an external store for the other nodes to use. Internally, zgroup uses the node with the highest IP(v4) address in the group.

## Sample binary

A [sample](./src/main.zig) binary is provided to show a way to use the library. There are two ways to run the sample:

* Specifying the join address manually
* Using an external service to get the join address

### Local with join address

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

### Local with an external service

If configured, the sample binary uses a free service, [https://keyvalue.immanuel.co/](https://keyvalue.immanuel.co/), as a store for the join address.

```sh
# Build the sample binary:
$ zig build --summary all

# Generate UUID:
$ uuidgen
{output}

# Run the 1st process. The expected args look like:
#
#   ./zgroup groupname member_ip:port
#

# Run the first process:
$ ZGROUP_JOIN_PREFIX={output} ./zig-out/bin/zgroup group1 0.0.0.0:8080

# Add a second node (different terminal):
$ ZGROUP_JOIN_PREFIX={output} ./zig-out/bin/zgroup group1 0.0.0.0:8081

# Add a third node (different terminal):
$ ZGROUP_JOIN_PREFIX={output} ./zig-out/bin/zgroup group1 0.0.0.0:8082

# Add a fourth node (different terminal):
$ ZGROUP_JOIN_PREFIX={output} ./zig-out/bin/zgroup group1 0.0.0.0:8083

# and so on...
```

### Kubernetes (Deployment)

A sample Kubernetes [deployment file](./k8s.yaml) is provided to try zgroup on [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/). Before deploying though, make sure to update the `ZGROUP_JOIN_PREFIX` environment variable, like so:

```sh
# Generate UUID:
$ uuidgen
{output}

# Update the 'value' part with your output.
  ...
  - name: ZGROUP_JOIN_PREFIX
    value: "{output}"
  ...

# Deploy to Kubernetes:
$ kubectl create -f k8s.yaml

# You will notice some initial errors in the logs.
# Wait for a while before the K/V store is updated.
```

### GCP Managed Instance Group (MIG)

A sample [startup script](./gcp-mig-startup.sh) is provided to try zgroup on a [GCP MIG](https://cloud.google.com/compute/docs/instance-groups#managed_instance_groups). Before deploying though, make sure to update the `ZGROUP_JOIN_PREFIX` value in the script, like so:

```sh
# Generate UUID:
$ uuidgen
{output}

# Update the 'value' part of ZGROUP_JOIN_PREFIX with your output.
...
ZGROUP_JOIN_PREFIX={output} ./zgroup group1 ...

# Create an instance template:
$ gcloud compute instance-templates create zgroup-tmpl \
  --machine-type e2-micro \
  --metadata=startup-script=''"$(cat gcp-mig-startup.sh)"''

# Create a regional MIG:
$ gcloud compute instance-groups managed create rmig \
  --template zgroup-tmpl --size 3 --region {your-region}

# You can view the logs through:
$ tail -f /var/log/messages
```

### AWS Autoscaling Group

A sample [startup script](./aws-asg-startup.sh) is provided to try zgroup on an [AWS ASG](https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-groups.html). Before deploying though, make sure to update the `ZGROUP_JOIN_PREFIX` value in the script, like so:

```sh
# Generate UUID:
$ uuidgen
{output}

# Update the 'value' part of ZGROUP_JOIN_PREFIX with your output.
...
ZGROUP_JOIN_PREFIX={output} ./zgroup group1 ...

# Create a launch template. ImageId here is Amazon Linux, default VPC.
# (Added newlines for readability. Might not run when copied as is.)
$ aws ec2 create-launch-template \
  --launch-template-name zgroup-lt \
  --version-description version1 \
  --launch-template-data '
  {
    "UserData":"'"$(cat aws-asg-startup.sh | base64 -w 0)"'",
    "ImageId":"ami-0f75d1a8c9141bd00",
    "InstanceType":"t2.micro"
  }'

# Create the ASG:
$ aws autoscaling create-auto-scaling-group \
  --auto-scaling-group-name zgroup-asg \
  --launch-template LaunchTemplateName=zgroup-lt,Version='1' \
  --min-size 3 \
  --max-size 3 \
  --availability-zones {target-zone}

# You can view the logs through:
$ [sudo] journalctl -f
```

## Getting the list of members

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

## TODOs

- [ ] - Provide callbacks for membership changes
- [ ] - Provide an API to get the current leader
- [ ] - Provide an interface for other processes (non-Zig users)
- [ ] - Use multicast (if available) for the join address

PR's are welcome.
