const std = @import("std");
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;

const log = std.log.scoped(.zgroup);

pub fn Group() type {
    return struct {
        const Self = @This();

        /// SWIM protocol generic commands.
        pub const Command = enum(u8) {
            dummy,
            ack,
            nack,
            join,
            ping,
            ping_req,
        };

        /// Infection-style dissemination (ISD) commands.
        pub const IsdCommand = enum(u8) {
            dummy,
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

        /// Our generic UDP comms/protocol payload.
        pub const Message = packed struct {
            name: u128 = 0,
            cmd: Command = .nack,
            isd_src_cmd: IsdCommand = .dummy,
            src_ip: u32 = 0,
            src_port: u16 = 0,
            src_state: MemberState = .alive,
            isd_dst_cmd: IsdCommand = .dummy,
            dst_ip: u32 = 0,
            dst_port: u16 = 0,
            dst_state: MemberState = .alive,
            incarnation: u64 = 0,
        };

        /// Per-member context data.
        pub const MemberData = struct {
            state: MemberState = .alive,
            ping_sweep: u1 = 0,
        };

        /// Config for init().
        pub const Config = struct {
            /// We use the name as group identifier when groups are running over the
            /// same network. At the moment, we use the UUID format as we can cast
            /// it to `u128` for easy network sending than, say, a `[]u8`. Use init()
            /// initialize.
            /// Example: "0xf47ac10b58cc4372a5670e02b2c3d479"
            name: []u8 = undefined,

            /// Member IP address for UDP, eg. "0.0.0.0". Use init() to initialize.
            ip: []u8 = undefined,

            /// Member port number for UDP, eg. 8080. Use init() to initialize.
            port: u16 = 8080,

            /// Our SWIM protocol timeout duration.
            protocol_time: u64 = std.time.ns_per_s * 2,

            /// Suspicion subprotocol timeout duration.
            suspected_time: u64 = std.time.ns_per_ms * 1500,

            /// Number of members we will request to do indirect pings for us (agents).
            /// Valid value at the moment is `1`.
            ping_req_k: u32 = 1,
        };

        /// Create an instance of Self based on Config.
        pub fn init(allocator: std.mem.Allocator, config: *const Config) !Self {
            return Self{
                .allocator = allocator,
                .name = config.name,
                .ip = config.ip,
                .port = config.port,
                .protocol_time = config.protocol_time,
                .suspected_time = config.suspected_time,
                .ping_req_k = config.ping_req_k,
                .members = std.StringHashMap(MemberData).init(allocator),
            };
        }

        /// Cleanup Self instance. At the moment, it is expected for this
        /// code to be long running until process is terminated.
        pub fn deinit(self: *Self) void {
            log.debug("deinit:", .{});

            // TODO:
            // 1. Free keys in members.
            // 2. Release members.
            // 3. Release isd_inbound.
            // 4. Release isd_outbound.
            // 5. See how to gracefuly exit threads.

            self.members.deinit();
        }

        /// Start group membership tracking.
        pub fn run(self: *Self) !void {
            const key = try std.fmt.allocPrint(
                self.allocator,
                "{s}:{d}",
                .{ self.ip, self.port },
            );

            try self.members.put(key, .{});

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

        const KeyState = struct {
            key: *[]const u8,
            state: MemberState,
        };

        allocator: std.mem.Allocator,

        /// We use the name as group identifier when groups are running over the
        /// same network. At the moment, we use the UUID format as we can cast
        /// it to `u128` for easy network sending than, say, a `[]u8`. Use init()
        /// initialize.
        /// Example: "0xf47ac10b58cc4372a5670e02b2c3d479"
        /// (Same comment as `Config`.)
        name: []u8,

        /// Member IP address for UDP, eg. "0.0.0.0". Use init() to initialize.
        /// (Same comment as `Config`.)
        ip: []u8,

        /// Member port number for UDP, eg. 8080. Use init() to initialize.
        /// (Same comment as `Config`.)
        port: u16,

        /// Our SWIM protocol timeout duration.
        /// (Same comment as `Config`.)
        protocol_time: u64,

        /// Suspicion subprotocol timeout duration.
        /// (Same comment as `Config`.)
        suspected_time: u64,

        // Our per-member data. Key format is "ip:port", eg. "0.0.0.0:8080".
        members: std.StringHashMap(MemberData),
        members_mtx: std.Thread.Mutex = .{},

        /// Number of members we will request to do indirect pings for us (agents).
        /// Valid value at the moment is `1`.
        /// (Same comment as `Config`.)
        ping_req_k: u32,

        // Internal: mark and sweep flag for round-robin pings.
        ping_sweep: u1 = 1,

        // Internal: incarnation number for suspicion subprotocol.
        incarnation: u64 = 0,

        // Run internal UDP server.
        fn listen(self: *Self) !void {
            log.info("Starting UDP server on :{d}...", .{self.port});

            const name = try std.fmt.parseUnsigned(u128, self.name, 0);
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

            const addr = try std.net.Address.resolveIp(self.ip, self.port);
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM,
                std.posix.IPPROTO.UDP,
            );

            defer std.posix.close(sock);
            try setWriteTimeout(sock, 5_000_000);
            try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
            var src_addr: std.os.linux.sockaddr = undefined;
            var src_addrlen: std.posix.socklen_t = @sizeOf(std.os.linux.sockaddr);

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

                const msg: *Message = @ptrCast(@alignCast(buf));

                switch (msg.isd_src_cmd) {
                    .infect => {
                        const ipb = std.mem.asBytes(&msg.src_ip);
                        var key = try std.fmt.allocPrint(
                            self.allocator, // not arena
                            "{d}.{d}.{d}.{d}:{d}",
                            .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.src_port },
                        );

                        const pkey: *[]const u8 = &key;
                        self.addOrSet(pkey, msg.src_state);
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

                switch (msg.isd_dst_cmd) {
                    .infect => {
                        const ipb = std.mem.asBytes(&msg.dst_ip);
                        var key = try std.fmt.allocPrint(
                            self.allocator, // not arena
                            "{d}.{d}.{d}.{d}:{d}",
                            .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.dst_port },
                        );

                        const pkey: *[]const u8 = &key;
                        self.addOrSet(pkey, msg.src_state);
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
                            self.addOrSet(pkey, .alive);

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
                        if (msg.name == name) msg.cmd = .ack;
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
                            const ipb = std.mem.asBytes(&msg.dst_ip);
                            var dst = try std.fmt.allocPrint(
                                arena.allocator(),
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.dst_port },
                            );

                            log.debug("*** try pinging {s}", .{dst});

                            var dummy = false;
                            const pdst: *[]const u8 = &dst;
                            const list: std.ArrayList(KeyState) = undefined;
                            const ack = self.ping(pdst, list, &dummy) catch false;
                            msg.cmd = .nack;
                            if (ack) msg.cmd = .ack;
                            _ = try std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            );

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
            var gtm = try std.time.Timer.start();
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

                var tm = try std.time.Timer.start();
                var key_ptr: ?*[]const u8 = null;
                var isd: ?std.ArrayList(KeyState) = null;
                var skip_sleep = false;

                {
                    // Search for a node to ping (round-robin).
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var iter = self.members.iterator();
                    while (iter.next()) |v| {
                        if (v.value_ptr.state != .alive) continue;
                        if (v.value_ptr.ping_sweep != self.ping_sweep) {
                            if (key_ptr) |_| {} else {
                                key_ptr = v.key_ptr;
                                break;
                            }
                        }
                    }
                }

                // Look for a random live non-faulty member to broadcast.
                if (key_ptr) |ping_key| {
                    var excludes: [1]*[]const u8 = .{ping_key};
                    isd = try self.pickRandomNonFaulty(arena.allocator(), &excludes, 2);
                }

                if (key_ptr) |ping_key| {
                    self.members_mtx.lock();
                    const ps = self.members.getPtr(ping_key.*).?;
                    ps.ping_sweep = ~ps.ping_sweep;
                    self.members_mtx.unlock();

                    log.debug("[{d}] try pinging {s}, broadcast {d}", .{
                        i,
                        ping_key.*,
                        if (isd) |v| v.items.len else 0,
                    });

                    if (isd) |v| {
                        for (v.items) |item| {
                            log.debug("[{d}] try pinging {s}, broadcast {s}", .{
                                i,
                                ping_key.*,
                                item.key.*,
                            });
                        }
                    }

                    var ping_me = false;
                    switch (self.ping(ping_key, isd, &ping_me) catch false) {
                        false => {
                            // Let's do indirect ping for this suspicious node.
                            var do_suspected = false;
                            var excludes: [1]*[]const u8 = .{ping_key};
                            const list = try self.pickRandomNonFaulty(
                                arena.allocator(),
                                &excludes,
                                self.ping_req_k,
                            );

                            if (list.items.len == 0) do_suspected = true else {
                                log.debug("[{d}] ping-req: agent={d}", .{
                                    i,
                                    list.items.len,
                                });

                                var ts = std.ArrayList(IndirectPing).init(arena.allocator());
                                for (list.items) |v| {
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

                            if (do_suspected) {
                                self.setMemberState(ping_key, .suspected);

                                // TODO: dissemination-style suspected propagation.

                                var sf = SuspectToFaulty{ .self = self, .key = ping_key };
                                const t = try std.Thread.spawn(.{}, Self.suspectToFaulty, .{&sf});
                                t.detach();
                            }
                        },
                        else => {
                            const n = self.nStates();
                            // `+` here is alive+suspected
                            if (ping_me and ((n[0] + n[1]) > 1)) skip_sleep = true else {
                                log.debug("[{d}] ack from {s}, me={any}, took {any}", .{
                                    i,
                                    ping_key.*,
                                    ping_me,
                                    std.fmt.fmtDuration(gtm.lap()),
                                });
                            }
                        },
                    }
                } else {
                    self.ping_sweep = ~self.ping_sweep;
                    skip_sleep = true;
                }

                const elapsed = tm.read();
                if (elapsed < self.protocol_time and !skip_sleep) {
                    const left = self.protocol_time - elapsed;
                    log.debug("[{d}] tick: sleep for {any}", .{ i, std.fmt.fmtDuration(left) });
                    std.time.sleep(left);
                }
            }
        }

        fn presetMessage(self: *Self, msg: *Message) !void {
            msg.name = try std.fmt.parseUnsigned(u128, self.name, 0);
            msg.cmd = .dummy;
            msg.isd_src_cmd = .dummy;
            msg.isd_dst_cmd = .dummy;
            msg.src_state = .alive;
            msg.dst_state = .alive;
        }

        // Pick random ping target excluding `excludes` and ourselves.
        fn pickRandomNonFaulty(
            self: *Self,
            allocator: std.mem.Allocator, // arena
            excludes: []*[]const u8,
            needs: usize,
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

            var limit = needs;
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
        fn ping(self: *Self, key: *[]const u8, isd: ?std.ArrayList(KeyState), me: *bool) !bool {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit(); // destroy arena in one go

            const split = std.mem.indexOf(u8, key.*, ":").?;
            const ip = key.*[0..split];
            const port = try std.fmt.parseUnsigned(u16, key.*[split + 1 ..], 10);
            if (std.mem.eql(u8, ip, self.ip) and port == self.port) {
                me.* = true;
                return true;
            }

            const buf = try arena.allocator().alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try self.presetMessage(msg);
            msg.cmd = .ping;

            // Piggybacking on pings for our infection-style member/state dissemination.
            if (isd) |isd_v| {
                switch (isd_v.items.len) {
                    1 => { // utilize the src_* section only
                        const pop = isd_v.items[0];
                        const split_b = std.mem.indexOf(u8, pop.key.*, ":").?;
                        const ip_b = pop.key.*[0..split_b];
                        const port_b = try std.fmt.parseUnsigned(u16, pop.key.*[split_b + 1 ..], 10);
                        const addr = try std.net.Address.resolveIp(ip_b, port_b);
                        msg.isd_src_cmd = .infect;
                        msg.src_ip = addr.in.sa.addr;
                        msg.src_port = port_b;
                        msg.src_state = pop.state;
                        msg.isd_dst_cmd = .dummy; // make dst_* invalid
                    },
                    2 => { // utilize both src_* and dst_* sections
                        const pop0 = isd_v.items[0];
                        const split0 = std.mem.indexOf(u8, pop0.key.*, ":").?;
                        const ip0 = pop0.key.*[0..split0];
                        const port0 = try std.fmt.parseUnsigned(u16, pop0.key.*[split0 + 1 ..], 10);
                        const addr0 = try std.net.Address.resolveIp(ip0, port0);
                        msg.isd_src_cmd = .infect;
                        msg.src_ip = addr0.in.sa.addr;
                        msg.src_port = port0;
                        msg.src_state = pop0.state;

                        const pop1 = isd_v.items[1];
                        const split1 = std.mem.indexOf(u8, pop1.key.*, ":").?;
                        const ip1 = pop1.key.*[0..split1];
                        const port1 = try std.fmt.parseUnsigned(u16, pop1.key.*[split1 + 1 ..], 10);
                        const addr1 = try std.net.Address.resolveIp(ip1, port1);
                        msg.isd_dst_cmd = .infect;
                        msg.dst_ip = addr1.in.sa.addr;
                        msg.dst_port = port1;
                        msg.dst_state = pop1.state;
                    },
                    else => {},
                }
            }

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
            ack: bool = false,
        };

        // To be run as a separate thread.
        fn indirectPing(args: *IndirectPing) !void {
            log.debug("==> thread: try pinging {s} via {s}", .{ args.dst.*, args.src.* });
            var arena = std.heap.ArenaAllocator.init(args.self.allocator);
            defer arena.deinit(); // destroy arena in one go

            var split = std.mem.indexOf(u8, args.src.*, ":").?;
            const ip = args.src.*[0..split];
            const port = try std.fmt.parseUnsigned(u16, args.src.*[split + 1 ..], 10);

            const buf = try arena.allocator().alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try args.self.presetMessage(msg);
            msg.cmd = .ping_req;

            split = std.mem.indexOf(u8, args.dst.*, ":").?;
            const dst_ip = args.dst.*[0..split];
            const dst_port = try std.fmt.parseUnsigned(u16, args.dst.*[split + 1 ..], 10);
            const dst_addr = try std.net.Address.resolveIp(dst_ip, dst_port);
            msg.dst_ip = dst_addr.in.sa.addr;
            msg.dst_port = dst_port;

            // TODO: Piggyback messages for our infection-style dissemination.

            args.self.send(ip, port, buf) catch |err| log.err("send failed: {any}", .{err});

            switch (msg.cmd) {
                .ack => {
                    log.debug("==> thread: got ack from {s}", .{args.src.*});
                    const ptr = &args.ack;
                    ptr.* = true;
                },
                else => {},
            }
        }

        // Helper function for internal one-shot send/recv. `ptr` here is
        // expected to be *Message. The same message ptr is used for both
        // request and response payloads.
        fn send(_: *Self, ip: []const u8, port: u16, ptr: []u8) !void {
            const msg: *Message = @ptrCast(@alignCast(ptr));
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
            _ = try std.posix.write(sock, std.mem.asBytes(msg));
            _ = try std.posix.recv(sock, ptr, 0);
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
            const split = std.mem.indexOf(u8, key.*, ":").?;
            const ip = key.*[0..split];
            const port = try std.fmt.parseUnsigned(u16, key.*[split + 1 ..], 10);
            return if (std.mem.eql(u8, ip, self.ip) and port == self.port) true else false;
        }

        fn setMemberState(self: *Self, key: *[]const u8, state: MemberState) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getPtr(key.*).?;
            ptr.state = state;
        }

        // Add a new member or update an existing member's state.
        fn addOrSet(self: *Self, key: *[]const u8, state: MemberState) void {
            const contains = b: {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                break :b self.members.contains(key.*);
            };

            if (contains) {
                self.setMemberState(key, state);
                return;
            }

            self.members_mtx.lock();
            self.members.put(key.*, .{ .state = state }) catch {};
            self.members_mtx.unlock();
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
            const ptr = args.self.members.getPtr(args.key.*).?;
            if (ptr.state == .suspected) ptr.state = .faulty;
        }

        fn removeMember(self: *Self, key: *[]const u8) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const fr = self.members.fetchRemove(key.*);
            self.allocator.free(fr.?.key);
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
