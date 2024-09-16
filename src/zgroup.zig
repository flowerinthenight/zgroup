//! zgroup is a library that can manage cluster membership and member failure detection.
//! It is based on the SWIM Protocol, specifically, SWIM+Inf.+Sus. variant of the gossip
//! protocol. Linux-only for now.
//!
//!   Ref: https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf
//!
const std = @import("std");
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;

const log = std.log.scoped(.zgroup);

pub fn Fleet() type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,

        // See Config comments for these fields.
        name: []const u8,
        ip: []const u8,
        port: u16,
        protocol_time: u64,
        suspected_time: u64,
        ping_req_k: u32,

        // Our per-member data. Key format is "ip:port", eg. "127.0.0.1:8080".
        members: std.StringHashMap(MemberData),
        members_mtx: std.Thread.Mutex = .{},

        // Intermediate member queue for round-robin pings and randomization.
        ping_queue: std.ArrayList([]const u8),

        // Internal queue for suspicion subprotocol.
        isd_queue: std.ArrayList(KeyInfo),
        isd_mtx: std.Thread.Mutex = .{},

        /// SWIM protocol generic commands.
        pub const Command = enum(u8) {
            noop,
            ack,
            nack,
            join,
            ping,
            ping_req,
        };

        /// Infection-style dissemination (ISD) commands.
        pub const IsdCommand = enum(u8) {
            noop,
            infect,
            suspect,
            confirm_alive,
            confirm_faulty,
        };

        /// Possible member states.
        pub const MemberState = enum(u8) {
            alive,
            suspected,
            faulty,
        };

        const KeyInfo = struct {
            key: []const u8,
            state: MemberState,
            incarnation: u64 = 0,
            isd_cmd: IsdCommand = .noop,
        };

        /// Our generic UDP comms/protocol payload.
        pub const Message = packed struct {
            name: u128 = 0,
            // Section for ping, ping_req, ack, nack.
            cmd: Command = .noop,
            src_ip: u32 = 0,
            src_port: u16 = 0,
            src_state: MemberState = .alive,
            src_incarnation: u64 = 0,
            dst_cmd: IsdCommand = .noop,
            dst_ip: u32 = 0,
            dst_port: u16 = 0,
            dst_state: MemberState = .alive,
            dst_incarnation: u64 = 0,
            // Infection-style dissemination section.
            isd_cmd: IsdCommand = .noop,
            isd_ip: u32 = 0,
            isd_port: u16 = 0,
            isd_state: MemberState = .alive,
            isd_incarnation: u64 = 0,
        };

        /// Per-member context data.
        pub const MemberData = struct {
            state: MemberState = .alive,
            age_faulty: std.time.Timer = undefined,
            incarnation: u64 = 0,
        };

        /// Config for init().
        pub const Config = struct {
            /// We use the name as group identifier when groups are running over the
            /// same network. At the moment, we use the UUID format as we can cast
            /// it to `u128` for easy network sending than, say, a `[]u8`. Use init()
            /// to initialize.
            /// Example: "0xf47ac10b58cc4372a5670e02b2c3d479"
            name: []const u8,

            /// Member IP address for UDP, eg. "0.0.0.0". Use init() to initialize.
            ip: []const u8,

            /// Member port number for UDP, eg. 8080.
            port: u16 = 8080,

            /// Our SWIM protocol timeout duration.
            protocol_time: u64 = std.time.ns_per_s * 2,

            /// Suspicion subprotocol timeout duration.
            suspected_time: u64 = std.time.ns_per_s * 2,

            /// Number of members we will request to do indirect pings for us (agents).
            /// Valid value at the moment is `1`.
            ping_req_k: u32 = 1,
        };

        /// Create an instance of Self based on `config`. The `allocator` will be stored
        /// internally as the main internal allocator. Arena is not recommended as it's
        /// going to be used in the internal UDP server and the main loop which are
        /// expected to be long-running. Some areas will utilize an arena allocator
        /// based on the input allocator when it's appropriate.
        pub fn init(allocator: std.mem.Allocator, config: *const Config) !Self {
            log.debug("init: {s}:{d}", .{ config.ip, config.port });
            return Self{
                .allocator = allocator,
                .name = config.name,
                .ip = config.ip,
                .port = config.port,
                .protocol_time = config.protocol_time,
                .suspected_time = config.suspected_time,
                .ping_req_k = config.ping_req_k,
                .members = std.StringHashMap(MemberData).init(allocator),
                .ping_queue = std.ArrayList([]const u8).init(allocator),
                .isd_queue = std.ArrayList(KeyInfo).init(allocator),
            };
        }

        /// Cleanup Self instance. At the moment, it is expected for this
        /// code to be long running until process is terminated.
        pub fn deinit(self: *Self) void {
            log.debug("deinit:", .{});

            // TODO:
            // 1. Free keys in members.
            // 2. See how to gracefuly exit threads.

            self.members.deinit();
            self.ping_queue.deinit();
            self.isd_queue.deinit();
        }

        /// Start group membership tracking.
        pub fn run(self: *Self) !void {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            try self.addOrSet(me, .alive, 0);

            const server = try std.Thread.spawn(.{}, Self.listen, .{self});
            server.detach();
            const ticker = try std.Thread.spawn(.{}, Self.tick, .{self});
            ticker.detach();
        }

        /// Ask an instance to join an existing group. `joined` will be
        /// set to true if joining is successful. We are joining the
        /// group through `dst_*`.
        pub fn join(
            self: *Self,
            name: []const u8,
            dst_ip: []const u8,
            dst_port: u16,
            joined: *bool,
        ) !void {
            log.info("joining via {s}:{any}, name={s}...", .{
                dst_ip,
                dst_port,
                name,
            });

            var parent = std.heap.ArenaAllocator.init(self.allocator);
            defer parent.deinit(); // destroy arena in one go
            const arena = parent.allocator();

            const buf = try arena.alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));

            try self.presetMessage(msg);
            msg.cmd = .join;
            try self.setMsgSrcToOwn(msg);

            try self.send(dst_ip, dst_port, buf);

            switch (msg.cmd) {
                .ack => {
                    const sname = try std.fmt.parseUnsigned(u128, self.name, 0);
                    if (sname == msg.name) {
                        const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{
                            dst_ip,
                            dst_port,
                        });

                        try self.addOrSet(key, .alive, 0);
                        joined.* = true;
                    }
                },
                else => {},
            }
        }

        // Run internal UDP server for comms.
        fn listen(self: *Self) !void {
            log.info("Starting UDP server on :{d}...", .{self.port});

            const name = try std.fmt.parseUnsigned(u128, self.name, 0);
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

            // One allocation for the duration of this function.
            const msg: *Message = @ptrCast(@alignCast(buf));

            const addr = try std.net.Address.resolveIp(self.ip, self.port);
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM,
                std.posix.IPPROTO.UDP,
            );

            defer std.posix.close(sock);
            try setWriteTimeout(sock, 5_000_000);
            try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
            var src_addr: std.posix.sockaddr = undefined;
            var src_addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

            var i: usize = 0;
            while (true) : (i += 1) {
                const len = std.posix.recvfrom(
                    sock,
                    buf,
                    0,
                    &src_addr,
                    &src_addrlen,
                ) catch |err| {
                    log.err("recvfrom failed: {any}", .{err});
                    std.time.sleep(std.time.ns_per_ms * 500);
                    continue;
                };

                var parent = std.heap.ArenaAllocator.init(self.allocator);
                defer parent.deinit(); // destroy arena in one go
                const arena = parent.allocator();

                switch (msg.isd_cmd) {
                    .infect => {
                        const key = try keyFromIpPort(arena, msg.isd_ip, msg.isd_port);
                        try self.setMemberInfo(key, msg.isd_state, msg.isd_incarnation);
                    },
                    .suspect => try self.handleSuspicion(arena, msg),
                    .confirm_alive => {
                        log.debug(">>>>> todo: confirm alive, inc={d}", .{msg.isd_incarnation});
                    },
                    .confirm_faulty => {
                        log.debug(">>>>> todo: confirm faulty", .{});
                    },
                    else => {},
                }

                // Main protocol message handler.
                switch (msg.cmd) {
                    .join => block: {
                        if (msg.name == name) {
                            const key = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            try self.addOrSet(key, .alive, msg.src_incarnation);

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            msg.cmd = .ack;
                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});

                            break :block; // return block
                        }

                        msg.cmd = .nack;
                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .ping => {
                        //
                        // Payload information:
                        //
                        //   src_*: caller/requester
                        //   dst_*: ISD (piggyback)
                        //   isd_*: ISD
                        //
                        msg.cmd = .nack; // default

                        if (msg.name == name) {
                            msg.cmd = .ack;
                            const src = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            try self.addOrSet(src, .alive, msg.src_incarnation);

                            if (msg.dst_cmd == .infect) {
                                const dst = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);
                                try self.addOrSet(dst, msg.dst_state, msg.dst_incarnation);
                            }

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            // Use both dst_* and isd_* for ISD info.
                            var excludes: [1][]const u8 = .{src};
                            try self.setDstAndIsd(arena, msg, &excludes);
                        }

                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .ping_req => block: {
                        //
                        // Payload information:
                        //
                        //   src_*: caller/requester (we are the agent)
                        //   dst_*: target of the ping-request
                        //   isd_*: ISD
                        //
                        if (msg.name == name) {
                            const src = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            try self.addOrSet(src, msg.src_state, msg.src_incarnation);

                            const dst = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);

                            log.debug("({d}) ping-req: requested to ping {s}", .{ len, dst });

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            // Use both dst_* and isd_* for ISD info.
                            var excludes: [1][]const u8 = .{dst};
                            try self.setDstAndIsd(arena, msg, &excludes);

                            const ack = self.ping(dst) catch false;

                            msg.cmd = .nack; // default

                            if (ack) {
                                // The src_* info here is the original ping target.
                                // Copy its info to the dst_* section before overwriting.
                                msg.cmd = .ack;
                                msg.dst_ip = msg.src_ip;
                                msg.dst_port = msg.src_port;
                                msg.dst_state = msg.src_state;
                                msg.dst_incarnation = msg.src_incarnation;

                                try self.addOrSet(dst, .alive, msg.src_incarnation);
                            }

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            const isd = try self.getIsdInfo(arena, 1);
                            if (isd.items.len > 0) {
                                msg.isd_cmd = .infect;
                                try setMsgSection(msg, .isd, isd.items[0]);
                            }

                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});

                            break :block; // return block
                        }

                        // Not in this group.
                        self.presetMessage(msg) catch {};
                        msg.cmd = .nack;

                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    else => {},
                }

                self.presetMessage(msg) catch {};
            }
        }

        // Thread running the SWIM protocol.
        fn tick(self: *Self) !void {
            var i: usize = 0;
            while (true) : (i += 1) {
                var parent = std.heap.ArenaAllocator.init(self.allocator);
                defer parent.deinit(); // destroy arena in one go
                const arena = parent.allocator();

                log.debug("[{d}]", .{i}); // log separator

                {
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var it = self.members.iterator();
                    while (it.next()) |v| {
                        log.debug("[{d}] members: key={s}, state={any}, inc={d}", .{
                            i,
                            v.key_ptr.*,
                            v.value_ptr.state,
                            v.value_ptr.incarnation,
                        });
                    }
                }

                try self.removeFaultyMembers();

                var tm = try std.time.Timer.start();
                var key_ptr: ?[]const u8 = null;

                const pt = try self.getPingTarget(arena);
                if (pt) |v| key_ptr = v; // ensure non-null

                if (key_ptr) |ping_key| {
                    log.debug("[{d}] try pinging {s}", .{ i, ping_key });

                    switch (self.ping(ping_key) catch false) {
                        false => {
                            // Let's do indirect ping for this suspicious node.
                            var do_suspected = false;
                            var excludes: [1][]const u8 = .{ping_key};
                            const agents = try self.getRandomMember(
                                arena,
                                &excludes,
                                self.ping_req_k,
                            );

                            if (agents.items.len == 0) do_suspected = true else {
                                log.debug("[{d}] ping-req: agent(s)={d}", .{ i, agents.items.len });

                                var ts = std.ArrayList(IndirectPing).init(arena);
                                for (agents.items) |v| {
                                    var td = IndirectPing{
                                        .self = self,
                                        .src = v.key,
                                        .dst = ping_key,
                                    };

                                    td.thr = try std.Thread.spawn(.{}, Self.indirectPing, .{&td});
                                    try ts.append(td);
                                }

                                for (ts.items) |td| td.thr.join(); // wait for all agents

                                var acks = false;
                                for (ts.items) |v| acks = acks or v.ack;
                                if (!acks) do_suspected = true;
                            }

                            // We need to do it here, not in indirectPing, as we need to wait for
                            // the aggregated result from all threads (although, only 1 for now).
                            if (do_suspected) {
                                var tmp = std.ArrayList(KeyInfo).init(arena);

                                const state = b: {
                                    var ms: MemberState = .suspected;
                                    self.members_mtx.lock();
                                    defer self.members_mtx.unlock();
                                    const ptr = self.members.getPtr(ping_key);
                                    if (ptr) |v| {
                                        ms = v.state;
                                        try tmp.append(.{
                                            .key = ping_key,
                                            .state = v.state,
                                            .incarnation = v.incarnation,
                                        });
                                    }

                                    break :b ms;
                                };

                                if (state == .alive) try self.setMemberInfo(
                                    ping_key,
                                    .suspected,
                                    null,
                                );

                                if (tmp.items.len > 0) {
                                    self.isd_mtx.lock();
                                    defer self.isd_mtx.unlock();
                                    try self.isd_queue.append(.{
                                        .key = ping_key,
                                        .state = tmp.items[0].state,
                                        .incarnation = tmp.items[0].incarnation,
                                        .isd_cmd = .suspect,
                                    });
                                }

                                var sf = SuspectToFaulty{ .self = self, .key = ping_key };
                                const t = try std.Thread.spawn(.{}, Self.suspectToFaulty, .{&sf});
                                t.detach();
                            }
                        },
                        else => {
                            log.debug("[{d}] ack from {s}", .{ i, ping_key });

                            // TEST: start
                            if (i == 10) {
                                log.debug("[{d}] --- trigger suspect for {s}", .{ i, ping_key });
                                self.isd_mtx.lock();
                                defer self.isd_mtx.unlock();
                                try self.isd_queue.append(.{
                                    .key = ping_key,
                                    .state = .suspected,
                                    .incarnation = 0,
                                    .isd_cmd = .suspect,
                                });
                            }
                            // TEST: end
                        },
                    }
                }

                const elapsed = tm.read();
                if (elapsed < self.protocol_time) {
                    const left = self.protocol_time - elapsed;
                    log.debug("[{d}] sleep for {any}", .{ i, std.fmt.fmtDuration(left) });
                    std.time.sleep(left);
                }
            }
        }

        // Round-robin for one sweep, then randomize before doing another sweep.
        // We are passing in an arena allocator here.
        fn getPingTarget(self: *Self, allocator: std.mem.Allocator) !?[]const u8 {
            while (true) {
                const pop = self.ping_queue.popOrNull();
                if (pop) |v| return v;

                block: {
                    var tl = std.ArrayList([]const u8).init(allocator);
                    defer tl.deinit();

                    {
                        self.members_mtx.lock();
                        defer self.members_mtx.unlock();
                        var iter = self.members.iterator();
                        while (iter.next()) |v| {
                            if (v.value_ptr.state == .faulty) continue;
                            if (self.keyIsMe(v.key_ptr.*)) continue;
                            try tl.append(v.key_ptr.*);
                        }
                    }

                    switch (tl.items.len) {
                        0 => return null, // probably just us
                        1 => {
                            try self.ping_queue.append(tl.items[0]);
                            break :block;
                        },
                        else => {},
                    }

                    const seed = std.crypto.random.int(u64);
                    var prng = std.rand.DefaultPrng.init(seed);
                    const random = prng.random();
                    while (true) {
                        switch (tl.items.len) {
                            0 => break,
                            1 => {
                                try self.ping_queue.append(tl.items[0]);
                                break;
                            },
                            else => {},
                        }

                        const rv = random.uintAtMost(u64, tl.items.len - 1);
                        try self.ping_queue.append(tl.items[rv]);
                        _ = tl.swapRemove(rv);
                    }
                }
            }

            unreachable;
        }

        // Caller is responsible for releasing the returned memory.
        // We are passing in an arena allocator here.
        fn getRandomMember(
            self: *Self,
            allocator: std.mem.Allocator,
            excludes: [][]const u8,
            max: usize,
        ) !std.ArrayList(KeyInfo) {
            var hm = std.AutoHashMap(u64, KeyInfo).init(allocator);
            defer hm.deinit(); // noop

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var iter = self.members.iterator();
                while (iter.next()) |v| {
                    if (v.value_ptr.state == .faulty) continue;
                    if (self.keyIsMe(v.key_ptr.*)) continue;
                    var eql: usize = 0;
                    for (excludes) |x| {
                        if (std.mem.eql(u8, x, v.key_ptr.*)) eql += 1;
                    }

                    if (eql > 0) continue;
                    try hm.put(hm.count(), .{
                        .key = v.key_ptr.*,
                        .state = v.value_ptr.state,
                        .incarnation = v.value_ptr.incarnation,
                    });
                }
            }

            var out = std.ArrayList(KeyInfo).init(allocator);

            var limit = max;
            if (limit > hm.count()) limit = hm.count();
            if (hm.count() == 1 and limit > 0) {
                const get = hm.get(0);
                if (get) |v| try out.append(.{
                    .key = v.key,
                    .state = v.state,
                    .incarnation = v.incarnation,
                });

                return out;
            }

            const seed = std.crypto.random.int(u64);
            var prng = std.rand.DefaultPrng.init(seed);
            const random = prng.random();
            for (0..limit) |_| {
                if (hm.count() == 0) break;
                while (true) {
                    if (hm.count() == 0) break;
                    const rv = random.uintAtMost(u64, hm.count() - 1);
                    const fr = hm.fetchRemove(rv);
                    if (fr) |v| try out.append(.{
                        .key = v.value.key,
                        .state = v.value.state,
                        .incarnation = v.value.incarnation,
                    });

                    break;
                }
            }

            return out;
        }

        // Caller is responsible for releasing the returned memory.
        // We are passing in an arena allocator here.
        fn getIsdInfo(
            self: *Self,
            allocator: std.mem.Allocator,
            max: usize,
        ) !std.ArrayList(KeyInfo) {
            var out = std.ArrayList(KeyInfo).init(allocator);
            self.isd_mtx.lock();
            defer self.isd_mtx.unlock();
            while (true) {
                const pop = self.isd_queue.popOrNull();
                if (pop) |v| try out.append(v) else break;
                if (out.items.len >= max) break;
            }

            return out;
        }

        // Setup both dst_* and isd_* sections of the payload.
        // We are passing in an arena allocator here.
        fn setDstAndIsd(
            self: *Self,
            allocator: std.mem.Allocator,
            msg: *Message,
            excludes: [][]const u8,
        ) !void {
            const dst = try self.getRandomMember(allocator, excludes, 1);
            if (dst.items.len > 0) {
                msg.dst_cmd = .infect;
                try setMsgSection(msg, .dst, dst.items[0]);
            }

            // Setup main ISD info.
            const isd = try self.getIsdInfo(allocator, 1);
            if (isd.items.len > 0) {
                msg.isd_cmd = isd.items[0].isd_cmd;
                try setMsgSection(msg, .isd, isd.items[0]);
            }
        }

        // Ping a peer for liveness. Expected format for `key` is "ip:port",
        // eg. "127.0.0.1:8080". For pings, we use the src_* payload fields
        // to identify us, the sender.
        fn ping(self: *Self, key: []const u8) !bool {
            var parent = std.heap.ArenaAllocator.init(self.allocator);
            defer parent.deinit(); // destroy arena in one go
            const arena = parent.allocator();

            const sep = std.mem.indexOf(u8, key, ":") orelse return false;
            const ip = key[0..sep];
            const port = try std.fmt.parseUnsigned(u16, key[sep + 1 ..], 10);
            if (std.mem.eql(u8, ip, self.ip) and port == self.port) return true;

            const buf = try arena.alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try self.presetMessage(msg);

            msg.cmd = .ping;
            try self.setMsgSrcToOwn(msg);

            // Use both dst_* and isd_* for ISD info.
            var excludes: [1][]const u8 = .{key};
            try self.setDstAndIsd(arena, msg, &excludes);

            try self.send(ip, port, buf);

            return switch (msg.cmd) {
                .ack => b: {
                    try self.addOrSet(key, .alive, msg.src_incarnation);

                    // Consume dst_* as piggybacked ISD info.
                    if (msg.dst_cmd == .infect) {
                        const k = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);
                        try self.addOrSet(k, msg.dst_state, msg.dst_incarnation);
                    }

                    // Consume isd_* as the main ISD info.
                    switch (msg.isd_cmd) {
                        .infect => {
                            const k = try keyFromIpPort(arena, msg.isd_ip, msg.isd_port);
                            try self.addOrSet(k, msg.isd_state, msg.isd_incarnation);
                        },
                        .suspect => try self.handleSuspicion(arena, msg),
                        .confirm_alive => {},
                        .confirm_faulty => {},
                        else => {},
                    }

                    break :b true;
                },
                else => false,
            };
        }

        const IndirectPing = struct {
            thr: std.Thread = undefined,
            self: *Self,
            src: []const u8, // agent
            dst: []const u8, // target
            ack: bool = false,
        };

        // To be run as a separate thread. Ask somebody else to do an indirect ping
        // for us, piggybacking on some of the messages we need to propagate.
        fn indirectPing(args: *IndirectPing) !void {
            log.debug("[thread] try pinging {s} via {s}", .{ args.dst, args.src });

            var parent = std.heap.ArenaAllocator.init(args.self.allocator);
            defer parent.deinit(); // destroy arena in one go
            const arena = parent.allocator();

            const sep = std.mem.indexOf(u8, args.src, ":") orelse return;
            const ip = args.src[0..sep];
            const port = try std.fmt.parseUnsigned(u16, args.src[sep + 1 ..], 10);

            const buf = try arena.alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try args.self.presetMessage(msg);
            msg.cmd = .ping_req;

            // Set src_* to our info, the sender.
            try args.self.setMsgSrcToOwn(msg);

            // The dst_* section is the target of our ping.
            try setMsgSection(msg, .dst, .{
                .key = args.dst,
                .state = .suspected, // will not be used
                .incarnation = 0, // will not be used
            });

            const isd = try args.self.getIsdInfo(arena, 1);
            if (isd.items.len > 0) {
                msg.isd_cmd = .infect;
                try setMsgSection(msg, .isd, isd.items[0]);
            }

            args.self.send(ip, port, buf) catch |err| log.err("send failed: {any}", .{err});

            switch (msg.cmd) {
                .ack => {
                    try args.self.addOrSet(args.src, msg.src_state, msg.src_incarnation);
                    try args.self.addOrSet(args.dst, msg.dst_state, msg.dst_incarnation);

                    // Consume isd_* as the main ISD info.
                    switch (msg.isd_cmd) {
                        .infect => {
                            const k = try keyFromIpPort(arena, msg.isd_ip, msg.isd_port);
                            try args.self.addOrSet(k, msg.isd_state, msg.isd_incarnation);
                        },
                        else => {},
                    }

                    const ptr = &args.ack;
                    ptr.* = true;
                },
                .nack => try args.self.addOrSet(
                    args.src,
                    msg.src_state,
                    msg.src_incarnation,
                ),
                else => {},
            }
        }

        // Helper function for internal one-shot send/recv. The same
        // message ptr is used for both request and response payloads.
        fn send(_: *Self, ip: []const u8, port: u16, msg: []u8) !void {
            const addr = try std.net.Address.resolveIp(ip, port);
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
                0,
            );

            defer std.posix.close(sock);
            try setReadTimeout(sock, 5_000_000);
            try setWriteTimeout(sock, 5_000_000);
            try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
            _ = try std.posix.write(sock, msg);
            _ = try std.posix.recv(sock, msg, 0);
        }

        // Handle the isd_* section of the message payload.
        // We are passing in an arena allocator here.
        fn handleSuspicion(self: *Self, allocator: std.mem.Allocator, msg: *Message) !void {
            const key = try keyFromIpPort(allocator, msg.isd_ip, msg.isd_port);
            if (self.keyIsMe(key)) {
                try self.IncrementIncarnation();
                const pkey = self.getPersistentKeyFromKey(key);
                if (pkey) |v| {
                    self.isd_mtx.lock();
                    defer self.isd_mtx.unlock();
                    try self.isd_queue.append(.{
                        .key = v,
                        .state = .alive,
                        .isd_cmd = .confirm_alive,
                        .incarnation = try self.getIncarnation(),
                    });
                }
            } else try self.setMemberInfo(key, .suspected, msg.isd_incarnation);
        }

        // NOTE: Not using locks; only atomic.
        fn getIncarnation(self: *Self) !u64 {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            const ptr = self.members.getPtr(me);
            if (ptr) |v| return @atomicLoad(
                u64,
                &v.incarnation,
                AtomicOrder.seq_cst,
            );

            unreachable;
        }

        // NOTE: Not using locks; only atomic.
        fn IncrementIncarnation(self: *Self) !void {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            const ptr = self.members.getPtr(me);
            if (ptr) |v|
                _ = @atomicRmw(
                    u64,
                    &v.incarnation,
                    AtomicRmwOp.Add,
                    1,
                    AtomicOrder.seq_cst,
                );
        }

        // Caller must free the returned memory.
        fn getOwnKey(self: *Self) ![]const u8 {
            return try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.ip, self.port });
        }

        // Expected format for `key` is ip:port, eg. 0.0.0.0:8080.
        fn keyIsMe(self: *Self, key: []const u8) bool {
            const sep = std.mem.indexOf(u8, key, ":") orelse return false;
            const ip = key[0..sep];
            const port = std.fmt.parseUnsigned(u16, key[sep + 1 ..], 10) catch return false;
            return if (std.mem.eql(u8, ip, self.ip) and port == self.port) true else false;
        }

        // Use the key from members when adding items (key) to the isd_queue.
        fn getPersistentKeyFromKey(self: *Self, key: []const u8) ?[]const u8 {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getKeyPtr(key);
            if (ptr) |v| return v.*;
            return null;
        }

        // Set default values for the message.
        fn presetMessage(self: *Self, msg: *Message) !void {
            msg.name = try std.fmt.parseUnsigned(u128, self.name, 0);
            msg.cmd = .noop;
            msg.src_state = .alive;
            msg.dst_cmd = .noop;
            msg.dst_state = .alive;
            msg.isd_cmd = .noop;
            msg.isd_state = .alive;
        }

        fn setMsgSrcToOwn(self: *Self, msg: *Message) !void {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            try setMsgSection(msg, .src, .{
                .key = me,
                .state = .alive,
                .incarnation = try self.getIncarnation(),
            });
        }

        // Add a new member or update an existing member's info. This function duplicates the key
        // using self.allocator when adding a new member, not when updating an existing one.
        fn addOrSet(self: *Self, key: []const u8, state: ?MemberState, incarnation: ?u64) !void {
            const contains = b: {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                break :b self.members.contains(key);
            };

            if (contains) {
                try self.setMemberInfo(key, state, incarnation);
                return;
            }

            {
                const nkey = try self.allocator.dupe(u8, key);
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                try self.members.put(nkey, .{ .age_faulty = try std.time.Timer.start() });
            }

            try self.setMemberInfo(key, state, incarnation);
        }

        // NOTE:
        //
        // Allowed:
        //   alive -> suspected
        //   suspected -> faulty
        //
        // Not allowed:
        //   alive -> faulty
        //   faulty -> suspected
        fn setMemberInfo(
            self: *Self,
            key: []const u8,
            state: ?MemberState,
            incarnation: ?u64,
        ) !void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getPtr(key);
            if (ptr) |v| {
                if (state) |s| {
                    if (v.state == .alive and s == .faulty) return;
                    if (v.state == .faulty and s != .alive) return;
                    if (v.state == .faulty and s == .alive) v.incarnation = 0;
                    v.state = s;
                }

                if (incarnation) |inc| v.incarnation = inc;
                if (v.state == .faulty) v.age_faulty.reset();
            }
        }

        const SuspectToFaulty = struct {
            self: *Self,
            key: []const u8,
        };

        // To be run as a separate thread. Keep it suspected
        // for a while before marking it as faulty.
        fn suspectToFaulty(args: *SuspectToFaulty) !void {
            // Pause for a bit before we set to faulty.
            std.time.sleep(args.self.suspected_time);

            {
                args.self.members_mtx.lock();
                defer args.self.members_mtx.unlock();
                const ptr = args.self.members.getPtr(args.key);
                if (ptr) |v| {
                    if (v.state == .suspected) {
                        v.state = .faulty;
                        v.age_faulty.reset();
                    }
                }
            }
        }

        // Attempt removing faulty members after some time.
        fn removeFaultyMembers(self: *Self) !void {
            var rml = std.ArrayList([]const u8).init(self.allocator);
            defer rml.deinit();

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var it = self.members.iterator();
                const limit = std.time.ns_per_min * 10; // TODO: expose
                while (it.next()) |v| {
                    if (v.value_ptr.state != .faulty) continue;
                    if (v.value_ptr.age_faulty.read() > limit) {
                        try rml.append(v.key_ptr.*);
                    }
                }
            }

            for (rml.items) |v| self.removeMember(v);
        }

        // Frees the memory used for `key` as well.
        fn removeMember(self: *Self, key: []const u8) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const fr = self.members.fetchRemove(key);
            if (fr) |v| self.allocator.free(v.key);
        }

        const MsgSection = enum {
            src,
            dst,
            isd,
        };

        // Set a section of the message payload with ip, port, and state info.
        fn setMsgSection(msg: *Message, section: MsgSection, info: KeyInfo) !void {
            const sep = std.mem.indexOf(u8, info.key, ":") orelse return;
            const ip = info.key[0..sep];
            const port = try std.fmt.parseUnsigned(u16, info.key[sep + 1 ..], 10);
            const addr = try std.net.Address.resolveIp(ip, port);

            switch (section) {
                .src => {
                    msg.src_ip = addr.in.sa.addr;
                    msg.src_port = port;
                    msg.src_state = info.state;
                    msg.src_incarnation = info.incarnation;
                },
                .dst => {
                    msg.dst_ip = addr.in.sa.addr;
                    msg.dst_port = port;
                    msg.dst_state = info.state;
                    msg.dst_incarnation = info.incarnation;
                },
                .isd => {
                    msg.isd_ip = addr.in.sa.addr;
                    msg.isd_port = port;
                    msg.isd_state = info.state;
                    msg.isd_incarnation = info.incarnation;
                },
            }
        }
    };
}

/// Converts an ip and port to a string with format ip:port, eg. "127.0.0.1:8080".
/// Caller is responsible for releasing the returned memory.
fn keyFromIpPort(allocator: std.mem.Allocator, ip: u32, port: u16) ![]const u8 {
    const ipb = std.mem.asBytes(&ip);
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{
        ipb[0],
        ipb[1],
        ipb[2],
        ipb[3],
        port,
    });
}

/// Set socket read timeout in microseconds. Linux only.
pub fn setReadTimeout(socket: std.posix.socket_t, read: ?u32) !void {
    std.debug.assert(read == null or read.? != 0);
    const micros = read orelse 0;
    const opt = std.posix.timeval{
        .tv_sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
        .tv_usec = @intCast(@mod(micros, std.time.us_per_s)),
    };

    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.toBytes(opt)[0..],
    );
}

/// Set socket write timeout in microseconds. Linux only.
pub fn setWriteTimeout(socket: std.posix.socket_t, write: ?u32) !void {
    std.debug.assert(write == null or write.? != 0);
    const micros = write orelse 0;
    const opt = std.posix.timeval{
        .tv_sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
        .tv_usec = @intCast(@mod(micros, std.time.us_per_s)),
    };

    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDTIMEO,
        std.mem.toBytes(opt)[0..],
    );
}
