const std = @import("std");
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;

const log = std.log.scoped(.zgroup);

pub fn Group() type {
    return struct {
        const Self = @This();

        /// SWIM protocol generic commands.
        pub const Command = enum(u8) {
            exit,
            ack,
            nack,
            join,
            ping,
            indirect_ping,
        };

        /// Infection-style dissemination (ISD) commands.
        pub const IsdCommand = enum(u8) {
            set_alive,
            suspect,
            confirm_alive,
            confirm_faulty,
        };

        /// Our generic UDP comms/protocol payload.
        pub const Message = packed struct {
            name: u128 = 0,
            cmd: Command = .nack,
            isd_cmd: IsdCommand = .def_alive,
            src_ip: u32 = 0,
            src_port: u16 = 0,
            dst_ip: u32 = 0,
            dst_port: u16 = 0,
            incarnation: u64 = 0,
        };

        pub const MemberState = enum(u8) {
            alive,
            suspected,
            faulty,
        };

        /// Per-member context data.
        pub const MemberData = struct {
            state: MemberState = .alive,
            ping_sweep: u1 = 0,
            ping_req_sweep: u1 = 0,
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
                .isd_inbound = std.ArrayList(Message).init(allocator),
                .isd_outbound = std.ArrayList(Message).init(allocator),
            };
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
            self.isd_inbound.deinit();
            self.isd_outbound.deinit();
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

                        log.debug("join: key={s}", .{key});

                        self.members_mtx.lock();
                        self.members.put(key, .{}) catch {};
                        self.members_mtx.unlock();
                        joined.* = true;
                    }
                },
                else => {},
            }
        }

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
        /// (Same comment as `Config`.)
        ping_req_k: u32,

        // Internal: mark and sweep flag for round-robin pings.
        ping_sweep: u1 = 1,

        // Internal: mark and sweep flag for agent(s) searches.
        ping_req_sweep: u1 = 1,

        // Internal: incarnation number for suspicion subprotocol.
        incarnation: u64 = 0,

        isd_inbound: std.ArrayList(Message),
        isd_inbound_mtx: std.Thread.Mutex = .{},
        isd_outbound: std.ArrayList(Message),
        isd_outbound_mtx: std.Thread.Mutex = .{},

        ev_suspected_me: std.Thread.ResetEvent = .{},
        ev_suspected_others: std.Thread.ResetEvent = .{},
        ev_suspected_to_alive: std.Thread.ResetEvent = .{},
        ev_removed: std.Thread.ResetEvent = .{},

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

                const msg: *Message = @ptrCast(@alignCast(buf));

                switch (msg.isd_cmd) {
                    .set_alive => {},
                    .suspect => {
                        // TODO:
                        // Check if we receive a `suspected` status in the current
                        // incarnation. If so, we increase our incarnation number,
                        // and need to broadcast a confirm_alive message to all.
                    },
                    .confirm_alive => {},
                    .confirm_faulty => {},
                }

                switch (msg.cmd) {
                    .join => {
                        if (msg.name == name) {
                            const ipb = std.mem.asBytes(&msg.src_ip);
                            var key = try std.fmt.allocPrint(
                                self.allocator,
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.src_port },
                            );

                            const exists = self.members.contains(key);
                            if (!exists) {
                                self.members_mtx.lock();
                                self.members.put(key, .{ .state = .alive }) catch {};
                                self.members_mtx.unlock();
                            } else {
                                const pkey: *[]const u8 = &key;
                                self.setMemberState(pkey, .alive);
                            }

                            msg.cmd = .ack;
                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});
                        } else {
                            msg.cmd = .nack;
                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});
                        }
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
                    .indirect_ping => {
                        if (msg.name == name) {
                            const ipb = std.mem.asBytes(&msg.dst_ip);
                            var dst = try std.fmt.allocPrint(
                                self.allocator,
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.dst_port },
                            );

                            defer self.allocator.free(dst);

                            log.debug("*** try pinging {s}", .{dst});

                            var dummy = false;
                            const pdst: *[]const u8 = &dst;
                            const ack = self.ping(pdst, &dummy) catch false;
                            msg.cmd = .nack;
                            if (ack) msg.cmd = .ack;
                            _ = try std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            );
                        } else {
                            msg.cmd = .nack;
                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});
                        }
                    },
                    else => {},
                }
            }
        }

        // Thread running the SWIM protocol.
        fn tick(self: *Self) !void {
            var gtm = try std.time.Timer.start();
            // var rml = std.ArrayList(*[]const u8).init(self.allocator);
            var i: usize = 0;
            while (true) : (i += 1) {
                log.debug("[{d}]", .{i}); // log separator

                // Gradually remove faulty nodes.
                // if (rml.popOrNull()) |key| self.removeMember(key);

                {
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var it = self.members.iterator();
                    while (it.next()) |entry| {
                        // if (entry.value_ptr.state == .faulty) rml.append(entry.key_ptr) catch {};
                        log.debug("[{d}] members: {s} {any}", .{
                            i,
                            entry.key_ptr.*,
                            entry.value_ptr.state,
                        });
                    }
                }

                var skip_sleep = false;
                var tm = try std.time.Timer.start();
                var ping_key: *[]const u8 = undefined;
                var found = false;

                {
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var iter = self.members.iterator();
                    while (iter.next()) |entry| {
                        if (entry.value_ptr.state != .alive) continue;
                        if (entry.value_ptr.ping_sweep != self.ping_sweep) {
                            ping_key = entry.key_ptr;
                            found = true;
                            break;
                        }
                    }
                }

                if (found) {
                    self.members_mtx.lock();
                    const ptr = self.members.getPtr(ping_key.*).?;
                    ptr.ping_sweep = ~ptr.ping_sweep;
                    self.members_mtx.unlock();

                    log.debug("[{d}] swim: try pinging {s}", .{ i, ping_key.* });

                    var ping_me = false;
                    const ok = self.ping(ping_key, &ping_me) catch false;
                    if (!ok) {
                        // Let's ask other members to do indirect ping's for us.
                        var agents = std.ArrayList(*[]const u8).init(self.allocator);
                        defer {
                            if (agents.items.len > 0) {
                                for (agents.items) |v| {
                                    self.members_mtx.lock();
                                    defer self.members_mtx.unlock();
                                    const pk = self.members.getPtr(v.*).?;
                                    pk.ping_req_sweep = ~pk.ping_req_sweep;
                                }
                            }

                            agents.deinit();
                        }

                        // [0] = # of members already requested for ping-req
                        // [1] = # of alive/suspected members
                        const n_k = b: {
                            self.members_mtx.lock();
                            defer self.members_mtx.unlock();
                            var it = self.members.iterator();
                            var n: [2]isize = .{ 0, 0 };
                            while (it.next()) |entry| {
                                if (try self.keyIsMe(entry.key_ptr)) continue;
                                if (std.mem.eql(u8, entry.key_ptr.*, ping_key.*)) continue;
                                if (entry.value_ptr.state != .alive) continue;
                                if (entry.value_ptr.state != .faulty) n[1] += 1;
                                if (entry.value_ptr.ping_req_sweep != self.ping_req_sweep) {
                                    try agents.append(entry.key_ptr);
                                    if (agents.items.len >= self.ping_req_k) break;
                                } else n[0] += 1;
                            }

                            break :b n;
                        };

                        log.debug("[{d}] indirect-ping: agents={d}, nk={d}", .{
                            i,
                            agents.items.len,
                            n_k,
                        });

                        // Reset our sweeper flag for the next round of agent(s) search.
                        // `2` here implies only us and the other suspected member.
                        if (n_k[0] == (n_k[1] - 2)) self.ping_req_sweep = ~self.ping_req_sweep;

                        var do_suspected = false;
                        if (agents.items.len > 0) {
                            var ts = std.ArrayList(IndirectPing).init(self.allocator);
                            defer ts.deinit();
                            for (agents.items) |v| {
                                var td = IndirectPing{ .self = self, .src = v, .dst = ping_key };
                                td.thread = try std.Thread.spawn(.{}, Self.indirectPing, .{&td});
                                try ts.append(td);
                            }

                            for (ts.items) |td| td.thread.join(); // wait for all agents
                            var ack = false;
                            for (ts.items) |v| ack = ack or v.ack;
                            if (!ack) do_suspected = true;
                        } else {
                            // Let's do the suspicion ourselves directly, without agent(s).
                            // `2` here implies only us and the other suspected member.
                            if (n_k[0] == (n_k[1] - 2)) do_suspected = true;
                            if (!do_suspected) {
                                if (n_k[0] + n_k[1] == 0) do_suspected = true;
                            }
                        }

                        if (do_suspected) {
                            self.setMemberState(ping_key, .suspected);

                            // TODO: dissemination-style suspected propagation.

                            var sf = SuspectToFaulty{ .self = self, .key = ping_key };
                            const t = try std.Thread.spawn(.{}, Self.suspectToFaulty, .{&sf});
                            t.detach();
                        }
                    } else {
                        const n = self.nStates();
                        if (ping_me and ((n[0] + n[1]) > 1)) { // alive + suspected
                            skip_sleep = true;
                        } else {
                            log.debug("[{d}] ack from {s}, me={any}, took {any}", .{
                                i,
                                ping_key.*,
                                ping_me,
                                std.fmt.fmtDuration(gtm.lap()),
                            });
                        }
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
            msg.cmd = .nack; // force a valid value
            msg.isd_cmd = .set_alive; // force a valid value
        }

        // Expected format for `key` is ip:port, eg. 0.0.0.0:8080.
        fn ping(self: *Self, key: *[]const u8, me: *bool) !bool {
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

            try self.send(ip, port, buf);

            var ret = false;
            switch (msg.cmd) {
                .ack => ret = true,
                else => {},
            }

            return ret;
        }

        const IndirectPing = struct {
            thread: std.Thread = undefined,
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
            msg.cmd = .indirect_ping;

            split = std.mem.indexOf(u8, args.dst.*, ":").?;
            const dst_ip = args.dst.*[0..split];
            const dst_port = try std.fmt.parseUnsigned(u16, args.dst.*[split + 1 ..], 10);
            const dst_addr = try std.net.Address.resolveIp(dst_ip, dst_port);
            msg.dst_ip = dst_addr.in.sa.addr;
            msg.dst_port = dst_port;

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
        // expected to be *Member. The same message ptr is used for both
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
            var it = self.members.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.state) {
                    .alive => n[0] += 1,
                    .suspected => n[1] += 1,
                    .faulty => n[2] += 1,
                }
            }

            n[3] = self.members.count();
            self.members_mtx.unlock();
            return n;
        }

        // Expected format for `key` is ip:port, eg. 0.0.0.0:8080.
        fn keyIsMe(self: *Self, key: *[]const u8) !bool {
            const split = std.mem.indexOf(u8, key.*, ":").?;
            const ip = key.*[0..split];
            const port = try std.fmt.parseUnsigned(u16, key.*[split + 1 ..], 10);
            if (std.mem.eql(u8, ip, self.ip) and port == self.port) return true;
            return false;
        }

        fn setMemberState(self: *Self, key: *[]const u8, state: MemberState) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getPtr(key.*).?;
            ptr.state = state;
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
