//! zgroup is a library that can manage cluster membership and member failure detection.
//! It is based on the SWIM Protocol, specifically, SWIM+Inf.+Sus. variant of the gossip
//! protocol. Linux-only for now.
//!
//!   Ref: https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf
//!
const std = @import("std");

const log = std.log.scoped(.zgroup);

pub fn Fleet() type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,

        // See Config comments for these fields.
        name: []u8,
        ip: []u8,
        port: u16,
        protocol_time: u64,
        suspected_time: u64,
        ping_req_k: u32,

        // Our per-member data. Key format is "ip:port", eg. "0.0.0.0:8080".
        members: std.StringHashMap(MemberData),
        members_mtx: std.Thread.Mutex = .{},

        // Intermediate member queue for round-robin pings and randomization.
        ping_queue: std.ArrayList(*[]const u8),

        // Internal: incarnation number for suspicion subprotocol.
        incarnation: u64 = 0,

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

        const KeyState = struct {
            key: *[]const u8,
            state: MemberState,
        };

        /// Our generic UDP comms/protocol payload.
        pub const Message = packed struct {
            name: u128 = 0,
            cmd: Command = .nack,
            src_ip: u32 = 0,
            src_port: u16 = 0,
            src_state: MemberState = .alive,
            dst_ip: u32 = 0,
            dst_port: u16 = 0,
            dst_state: MemberState = .alive,
            isd1_cmd: IsdCommand = .noop,
            isd1_ip: u32 = 0,
            isd1_port: u16 = 0,
            isd1_state: MemberState = .alive,
            isd2_cmd: IsdCommand = .noop,
            isd2_ip: u32 = 0,
            isd2_port: u16 = 0,
            isd2_state: MemberState = .alive,
            incarnation: u64 = 0,
        };

        /// Per-member context data.
        pub const MemberData = struct {
            state: MemberState = .alive,
            age_faulty: std.time.Timer = undefined,
        };

        /// Config for init().
        pub const Config = struct {
            /// We use the name as group identifier when groups are running over the
            /// same network. At the moment, we use the UUID format as we can cast
            /// it to `u128` for easy network sending than, say, a `[]u8`. Use init()
            /// to initialize.
            /// Example: "0xf47ac10b58cc4372a5670e02b2c3d479"
            name: []u8 = undefined,

            /// Member IP address for UDP, eg. "0.0.0.0". Use init() to initialize.
            ip: []u8 = undefined,

            /// Member port number for UDP, eg. 8080.
            port: u16 = 8080,

            /// Our SWIM protocol timeout duration.
            protocol_time: u64 = std.time.ns_per_s * 2,

            /// Suspicion subprotocol timeout duration.
            suspected_time: u64 = std.time.ns_per_ms * 1500,

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
                .ping_queue = std.ArrayList(*[]const u8).init(allocator),
            };
        }

        /// Cleanup Self instance. At the moment, it is expected for this
        /// code to be long running until process is terminated.
        pub fn deinit(self: *Self) void {
            log.debug("deinit:", .{});

            // TODO:
            // 1. Free keys in members.
            // 2. Release members.
            // 3. See how to gracefuly exit threads.

            self.members.deinit();
            self.ping_queue.deinit();
        }

        /// Start group membership tracking.
        pub fn run(self: *Self) !void {
            var key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.ip, self.port });
            const pkey: *[]const u8 = &key;
            try self.addOrSet(pkey, .alive);

            const server = try std.Thread.spawn(.{}, Self.listen, .{self});
            server.detach();
            const ticker = try std.Thread.spawn(.{}, Self.tick, .{self});
            ticker.detach();
        }

        /// Ask an instance to join an existing group. `joined` will be set to true if
        /// joining is successful. `src_*` is the caller, joining through `dst_*`.
        pub fn join(
            self: *Self,
            name: []const u8,
            src_ip: []const u8,
            src_port: u16,
            dst_ip: []const u8,
            dst_port: u16,
            joined: *bool,
        ) !void {
            log.info("joining via {s}:{any}, name={s}...", .{ dst_ip, dst_port, name });

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit(); // destroy arena in one go

            const buf = try arena.allocator().alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try self.presetMessage(msg);
            msg.cmd = .join;
            const src_addr = try std.net.Address.resolveIp(src_ip, src_port);
            const dst_addr = try std.net.Address.resolveIp(dst_ip, dst_port);
            msg.src_ip = src_addr.in.sa.addr;
            msg.src_port = src_port;
            msg.dst_ip = dst_addr.in.sa.addr;
            msg.dst_port = dst_port;

            try self.send(dst_ip, dst_port, buf);

            switch (msg.cmd) {
                .ack => {
                    const sname = try std.fmt.parseUnsigned(u128, self.name, 0);
                    if (sname == msg.name) {
                        const ipb = std.mem.asBytes(&msg.dst_ip);
                        const key = try std.fmt.allocPrint(
                            self.allocator, // not arena
                            "{d}.{d}.{d}.{d}:{d}",
                            .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.dst_port },
                        );

                        self.members_mtx.lock();
                        self.members.put(key, .{}) catch {};
                        self.members_mtx.unlock();
                        joined.* = true;
                    }
                },
                else => {},
            }
        }

        // Run internal UDP server.
        fn listen(self: *Self) !void {
            log.info("Starting UDP server on :{d}...", .{self.port});

            const name = try std.fmt.parseUnsigned(u128, self.name, 0);
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

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

            while (true) {
                _ = std.posix.recvfrom(
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

                var arena = std.heap.ArenaAllocator.init(self.allocator);
                defer arena.deinit();

                switch (msg.isd1_cmd) {
                    .infect => {
                        const ipb = std.mem.asBytes(&msg.isd1_ip);
                        var key = try std.fmt.allocPrint(
                            self.allocator, // not arena
                            "{d}.{d}.{d}.{d}:{d}",
                            .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.isd1_port },
                        );

                        const pkey: *[]const u8 = &key;
                        try self.addOrSet(pkey, msg.isd1_state);
                    },
                    .suspect => {
                        // TODO:
                        // Check if we receive a `suspected` status in the current
                        // incarnation. If so, we increase our incarnation number,
                        // and need to broadcast a confirm_alive message to all.
                    },
                    .confirm_alive => {},
                    .confirm_faulty => {},
                    else => {},
                }

                switch (msg.isd2_cmd) {
                    .infect => {
                        const ipb = std.mem.asBytes(&msg.isd2_ip);
                        var key = try std.fmt.allocPrint(
                            self.allocator, // not arena
                            "{d}.{d}.{d}.{d}:{d}",
                            .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.isd2_port },
                        );

                        const pkey: *[]const u8 = &key;
                        try self.addOrSet(pkey, msg.isd2_state);
                    },
                    .suspect => {
                        // TODO:
                        // Check if we receive a `suspected` status in the current
                        // incarnation. If so, we increase our incarnation number,
                        // and need to broadcast a confirm_alive message to all.
                    },
                    .confirm_alive => {},
                    .confirm_faulty => {},
                    else => {},
                }

                switch (msg.cmd) {
                    .join => block: {
                        if (msg.name == name) {
                            const ipb = std.mem.asBytes(&msg.src_ip);
                            var key = try std.fmt.allocPrint(
                                self.allocator, // not arena
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.src_port },
                            );

                            const pkey: *[]const u8 = &key;
                            try self.addOrSet(pkey, .alive);

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
                        msg.cmd = .nack;
                        if (msg.name == name) {
                            msg.cmd = .ack;
                            const ipb = std.mem.asBytes(&msg.src_ip);
                            var key = try std.fmt.allocPrint(
                                self.allocator, // not arena
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.src_port },
                            );

                            const pkey: *[]const u8 = &key;
                            try self.addOrSet(pkey, .alive);
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
                        if (msg.name == name) {
                            const dip = std.mem.asBytes(&msg.dst_ip);
                            var dst = try std.fmt.allocPrint(
                                arena.allocator(),
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ dip[0], dip[1], dip[2], dip[3], msg.dst_port },
                            );

                            log.debug("ping-req: requested to ping {s}", .{dst});

                            const pdst: *[]const u8 = &dst;
                            const ack = self.ping(pdst, null) catch false;
                            msg.cmd = .nack;
                            if (ack) msg.cmd = .ack;

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
                    else => {},
                }

                self.presetMessage(msg) catch {};
            }
        }

        // Thread running the SWIM protocol.
        fn tick(self: *Self) !void {
            var i: usize = 0;
            while (true) : (i += 1) {
                var arena = std.heap.ArenaAllocator.init(self.allocator);
                defer arena.deinit();

                log.debug("[{d}]", .{i}); // log separator

                {
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var it = self.members.iterator();
                    while (it.next()) |entry| {
                        log.debug("[{d}] members: key={s}, state={any}", .{
                            i,
                            entry.key_ptr.*,
                            entry.value_ptr.state,
                        });
                    }
                }

                try self.removeFaultyMembers();

                var tm = try std.time.Timer.start();
                var key_ptr: ?*[]const u8 = null;
                var isd: ?std.ArrayList(KeyState) = null;

                const pt = try self.selectPingTarget(arena.allocator());
                if (pt) |v| key_ptr = v;

                // Look for a random live non-faulty member(s) to broadcast.
                if (key_ptr) |ping_key| {
                    var excludes: [1]*[]const u8 = .{ping_key};
                    isd = try self.pickRandomNonFaulty(arena.allocator(), &excludes, 2);
                }

                if (key_ptr) |ping_key| {
                    log.debug("[{d}] try pinging {s}, broadcast(s)={d}", .{
                        i,
                        ping_key.*,
                        if (isd) |v| v.items.len else 0,
                    });

                    switch (self.ping(ping_key, isd) catch false) {
                        false => {
                            // Let's do indirect ping for this suspicious node.
                            var do_suspected = false;
                            var excludes: [1]*[]const u8 = .{ping_key};
                            const agents = try self.pickRandomNonFaulty(
                                arena.allocator(),
                                &excludes,
                                self.ping_req_k,
                            );

                            if (agents.items.len == 0) do_suspected = true else {
                                log.debug("[{d}] ping-req: agent(s)={d}", .{ i, agents.items.len });

                                var ts = std.ArrayList(IndirectPing).init(arena.allocator());
                                for (agents.items) |v| {
                                    var td = IndirectPing{
                                        .self = self,
                                        .src = v.key,
                                        .dst = ping_key,
                                        .isd = isd,
                                    };

                                    td.thr = try std.Thread.spawn(.{}, Self.indirectPing, .{&td});
                                    try ts.append(td);
                                }

                                for (ts.items) |td| td.thr.join(); // wait for all agents

                                var acks = false;
                                for (ts.items) |v| acks = acks or v.ack;
                                if (!acks) do_suspected = true else {
                                    try self.addOrSet(ping_key, .alive);
                                }
                            }

                            if (do_suspected) {
                                self.setMemberState(ping_key, .suspected);
                                var sf = SuspectToFaulty{ .self = self, .key = ping_key };
                                const t = try std.Thread.spawn(.{}, Self.suspectToFaulty, .{&sf});
                                t.detach();
                            }
                        },
                        else => {
                            try self.addOrSet(ping_key, .alive);
                            log.debug("[{d}] ack from {s}", .{ i, ping_key.* });
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
        fn selectPingTarget(self: *Self, allocator: std.mem.Allocator) !?*[]const u8 {
            while (true) {
                const pop = self.ping_queue.popOrNull();
                if (pop) |v| return v;

                block: {
                    var tl = std.ArrayList(*[]const u8).init(allocator);
                    defer tl.deinit();

                    {
                        self.members_mtx.lock();
                        defer self.members_mtx.unlock();
                        var iter = self.members.iterator();
                        while (iter.next()) |v| {
                            if (v.value_ptr.state == .faulty) continue;
                            if (try self.keyIsMe(v.key_ptr)) continue;
                            try tl.append(v.key_ptr);
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

        // Pick random ping target excluding `excludes` and ourselves. The return ArrayList
        // will be owned by the caller and is expected to be freed outside of this function.
        fn pickRandomNonFaulty(
            self: *Self,
            allocator: std.mem.Allocator, // arena
            excludes: []*[]const u8,
            max: usize,
        ) !std.ArrayList(KeyState) {
            var out = std.ArrayList(KeyState).init(allocator);
            var hm = std.AutoHashMap(u64, KeyState).init(allocator);
            defer hm.deinit(); // noop

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var iter = self.members.iterator();
                while (iter.next()) |v| {
                    if (v.value_ptr.state == .faulty) continue;
                    if (try self.keyIsMe(v.key_ptr)) continue;
                    var eql: usize = 0;
                    for (excludes) |ex| {
                        if (std.mem.eql(u8, ex.*, v.key_ptr.*)) eql += 1;
                    }

                    if (eql > 0) continue;
                    try hm.put(hm.count(), .{
                        .key = v.key_ptr,
                        .state = v.value_ptr.state,
                    });
                }
            }

            var limit = max;
            if (limit > hm.count()) limit = hm.count();
            if (hm.count() == 1 and limit > 0) {
                const get = hm.get(0);
                if (get) |v| try out.append(.{ .key = v.key, .state = v.state });
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
                    if (fr) |v| try out.append(.{ .key = v.value.key, .state = v.value.state });
                    break;
                }
            }

            return out;
        }

        // Expected format for `key` is ip:port, eg. 0.0.0.0:8080.
        fn ping(self: *Self, key: *[]const u8, isd: ?std.ArrayList(KeyState)) !bool {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit(); // destroy arena in one go

            const sep = std.mem.indexOf(u8, key.*, ":") orelse return false;
            const ip = key.*[0..sep];
            const port = try std.fmt.parseUnsigned(u16, key.*[sep + 1 ..], 10);
            if (std.mem.eql(u8, ip, self.ip) and port == self.port) return true;

            const buf = try arena.allocator().alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try self.presetMessage(msg);

            msg.cmd = .ping;
            var me = try std.fmt.allocPrint(arena.allocator(), "{s}:{d}", .{ self.ip, self.port });
            const pme: *[]const u8 = &me;
            try self.setMessageSection(msg, .src, .{ .key = pme, .state = .alive });

            if (isd) |isd_v| try self.setIsdInfo(msg, isd_v); // piggyback isd

            try self.send(ip, port, buf);

            return switch (msg.cmd) {
                .ack => true,
                else => false,
            };
        }

        const IndirectPing = struct {
            thr: std.Thread = undefined,
            self: *Self,
            src: *[]const u8 = undefined, // agent
            dst: *[]const u8 = undefined, // target
            isd: ?std.ArrayList(KeyState) = null,
            ack: bool = false,
        };

        // To be run as a separate thread.
        fn indirectPing(args: *IndirectPing) !void {
            log.debug("[thread] try pinging {s} via {s}", .{ args.dst.*, args.src.* });
            var arena = std.heap.ArenaAllocator.init(args.self.allocator);
            defer arena.deinit(); // destroy arena in one go

            const sep = std.mem.indexOf(u8, args.src.*, ":") orelse return;
            const ip = args.src.*[0..sep];
            const port = try std.fmt.parseUnsigned(u16, args.src.*[sep + 1 ..], 10);

            const buf = try arena.allocator().alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try args.self.presetMessage(msg);
            msg.cmd = .ping_req;

            // Use the src section for infection-style info dissemination.
            var me = try std.fmt.allocPrint(
                arena.allocator(),
                "{s}:{d}",
                .{ args.self.ip, args.self.port },
            );

            const pme: *[]const u8 = &me;
            try args.self.setMessageSection(msg, .src, .{ .key = pme, .state = .alive });

            // The dst_* section is the target of our ping.
            try args.self.setMessageSection(msg, .dst, .{
                .key = args.dst,
                .state = .suspected, // will not be used
            });

            if (args.isd) |isd| try args.self.setIsdInfo(msg, isd); // piggyback isd

            args.self.send(ip, port, buf) catch |err| log.err("send failed: {any}", .{err});

            switch (msg.cmd) {
                .ack => {
                    try args.self.addOrSet(args.src, .alive);
                    log.debug("[thread] got ack from {s}", .{args.src.*});
                    const ptr = &args.ack;
                    ptr.* = true;
                },
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

        // [0] = # of alive members
        // [1] = # of suspected members
        // [2] = # of faulty members
        // [3] = total number of members
        fn nStates(self: *Self) [4]usize {
            var n: [4]usize = .{ 0, 0, 0, 0 };
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            var it = self.members.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.state) {
                    .alive => n[0] += 1,
                    .suspected => n[1] += 1,
                    .faulty => n[2] += 1,
                }
            }

            n[3] = self.members.count();
            return n;
        }

        // Expected format for `key` is ip:port, eg. 0.0.0.0:8080.
        fn keyIsMe(self: *Self, key: *[]const u8) !bool {
            const sep = std.mem.indexOf(u8, key.*, ":") orelse return false;
            const ip = key.*[0..sep];
            const port = try std.fmt.parseUnsigned(u16, key.*[sep + 1 ..], 10);
            return if (std.mem.eql(u8, ip, self.ip) and port == self.port) true else false;
        }

        // Set default values for the message.
        fn presetMessage(self: *Self, msg: *Message) !void {
            msg.name = try std.fmt.parseUnsigned(u128, self.name, 0);
            msg.cmd = .noop;
            msg.src_state = .alive;
            msg.dst_state = .alive;
            msg.isd1_cmd = .noop;
            msg.isd2_cmd = .noop;
            msg.isd1_state = .alive;
            msg.isd2_state = .alive;
        }

        const MessageSection = enum {
            src,
            dst,
            isd1,
            isd2,
        };

        // Set a section of the message payload with ip, port, and state info.
        fn setMessageSection(
            _: *Self,
            msg: *Message,
            section: MessageSection,
            info: KeyState,
        ) !void {
            const sep = std.mem.indexOf(u8, info.key.*, ":") orelse return;
            const ip = info.key.*[0..sep];
            const port = try std.fmt.parseUnsigned(u16, info.key.*[sep + 1 ..], 10);
            const addr = try std.net.Address.resolveIp(ip, port);

            switch (section) {
                .src => {
                    msg.src_ip = addr.in.sa.addr;
                    msg.src_port = port;
                    msg.src_state = info.state;
                },
                .dst => {
                    msg.dst_ip = addr.in.sa.addr;
                    msg.dst_port = port;
                    msg.dst_state = info.state;
                },
                .isd1 => {
                    msg.isd1_ip = addr.in.sa.addr;
                    msg.isd1_port = port;
                    msg.isd1_state = info.state;
                },
                .isd2 => {
                    msg.isd2_ip = addr.in.sa.addr;
                    msg.isd2_port = port;
                    msg.isd2_state = info.state;
                },
            }
        }

        // Set a section of the message payload with ISD info.
        // ISD = Infection-style dissemination.
        fn setIsdInfo(self: *Self, msg: *Message, isd: std.ArrayList(KeyState)) !void {
            switch (isd.items.len) {
                0 => return,
                1 => b: { // utilize the isd1_* section only
                    const pop1 = isd.items[0];
                    msg.isd1_cmd = .infect;
                    msg.isd2_cmd = .noop; // don't use isd2_*
                    self.setMessageSection(msg, .isd1, .{
                        .key = pop1.key,
                        .state = pop1.state,
                    }) catch break :b;
                },
                else => b: { // utilize both isd1_* and isd2_* sections
                    const pop1 = isd.items[0];
                    msg.isd1_cmd = .infect;
                    self.setMessageSection(msg, .isd1, .{
                        .key = pop1.key,
                        .state = pop1.state,
                    }) catch break :b;

                    const pop2 = isd.items[1];
                    msg.isd2_cmd = .infect;
                    self.setMessageSection(msg, .isd2, .{
                        .key = pop2.key,
                        .state = pop2.state,
                    }) catch break :b;
                },
            }
        }

        fn setMemberState(self: *Self, key: *[]const u8, state: MemberState) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getPtr(key.*);
            if (ptr) |u| {
                u.state = state;
                if (u.state == .faulty) u.age_faulty.reset();
            }
        }

        // Add a new member or update an existing member's state.
        fn addOrSet(self: *Self, key: *[]const u8, state: MemberState) !void {
            const contains = b: {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                break :b self.members.contains(key.*);
            };

            if (contains) {
                self.setMemberState(key, state);
                return;
            }

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                try self.members.put(key.*, .{
                    .state = state,
                    .age_faulty = try std.time.Timer.start(),
                });
            }
        }

        const SuspectToFaulty = struct {
            self: *Self,
            key: *[]const u8,
        };

        // To be run as a separate thread.
        fn suspectToFaulty(args: *SuspectToFaulty) !void {
            std.time.sleep(args.self.suspected_time);
            args.self.members_mtx.lock();
            defer args.self.members_mtx.unlock();
            const ptr = args.self.members.getPtr(args.key.*);
            if (ptr) |u| {
                if (u.state == .suspected) {
                    u.state = .faulty;
                    u.age_faulty.reset();
                }
            }
        }

        fn removeMember(self: *Self, key: *[]const u8) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const fr = self.members.fetchRemove(key.*);
            if (fr) |u| self.allocator.free(u.key);
        }

        fn removeFaultyMembers(self: *Self) !void {
            var rml = std.ArrayList(*[]const u8).init(self.allocator);
            defer rml.deinit();

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var it = self.members.iterator();
                const limit = std.time.ns_per_min * 10;
                while (it.next()) |entry| {
                    if (entry.value_ptr.state != .faulty) continue;
                    if (entry.value_ptr.age_faulty.read() > limit) {
                        try rml.append(entry.key_ptr);
                    }
                }
            }

            for (rml.items) |v| self.removeMember(v);
        }
    };
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
