const std = @import("std");
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;

const log = std.log.scoped(.zgroup);

pub fn Group() type {
    return struct {
        const Self = @This();

        pub const Command = enum(u8) {
            exit,
            dummy,
            join,
            ping,
            ping_req,
            ack,
            suspect,
            alive,
            confirm_faulty,
        };

        pub const Message = packed struct {
            cmd: Command = .dummy,
            name: u128 = 0,
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

        pub const MemberData = struct {
            state: MemberState = .alive,
            sweep: u1 = 0,
        };

        pub const Config = struct {
            // Format: hexstring, i.e. "0xf47ac10b58cc4372a5670e02b2c3d479".
            name: []u8 = undefined,

            // Format: IP address, i.e. "0.0.0.0".
            ip: []u8 = undefined,

            // UDP port for this node, i.e. 8080.
            port: u16 = 0,
        };

        /// Create an instance of Self based on Config.
        pub fn init(allocator: std.mem.Allocator, config: *const Config) !Self {
            return Self{
                .allocator = allocator,
                .name = config.name,
                .ip = config.ip,
                .port = config.port,
                .members = std.StringHashMap(MemberData).init(allocator),
            };
        }

        /// Start group membership tracking.
        pub fn run(self: *Self) !void {
            const key = try std.fmt.allocPrint(
                self.allocator,
                "{s}:{d}",
                .{ self.ip, self.port },
            );

            try self.members.put(key, .{ .state = .alive });
            const server = try std.Thread.spawn(.{}, Self.listen, .{self});
            server.detach();
            const ticker = try std.Thread.spawn(.{}, Self.tick, .{self});
            ticker.detach();
        }

        /// Cleanup Self instance. At the moment, it is expected for this
        /// code to be long running until process is terminated.
        pub fn deinit(self: *Self) void {
            // TODO:
            // 1. Free keys in members.
            // 2. Release members.
            // 3. See how to gracefuly exit threads.

            log.info("deinit:", .{});

            self.members.deinit();
        }

        /// Ask an instance to join an existing group.
        pub fn join(
            self: *Self,
            name: []const u8,
            src_ip: []const u8,
            src_port: u16,
            dst_ip: []const u8,
            dst_port: u16,
        ) !void {
            log.info("joining through {s}:{any}/{s}...", .{ dst_ip, dst_port, name });

            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer
            const msg: *Message = @ptrCast(@alignCast(buf));
            msg.cmd = .join;
            msg.name = try std.fmt.parseUnsigned(u128, name, 0);
            const src_addr = try std.net.Address.resolveIp(src_ip, src_port);
            const dst_addr = try std.net.Address.resolveIp(dst_ip, dst_port);
            msg.src_ip = src_addr.in.sa.addr;
            msg.src_port = src_port;
            msg.dst_ip = dst_addr.in.sa.addr;
            msg.dst_port = dst_port;
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
                0,
            );

            defer std.posix.close(sock);
            try setReadTimeout(sock, 5_000_000);
            try setWriteTimeout(sock, 5_000_000);
            try std.posix.connect(sock, &dst_addr.any, dst_addr.getOsSockLen());
            _ = try std.posix.write(sock, std.mem.asBytes(msg));
            const len = try std.posix.recv(sock, buf, 0);

            switch (msg.cmd) {
                .ack => {
                    log.info("{d}: reply: cmd={any}, name=0x{x}", .{ len, msg.cmd, msg.name });

                    const hex = try std.fmt.parseUnsigned(u128, self.name, 0);
                    if (hex == msg.name) {
                        const ipb = std.mem.asBytes(&msg.dst_ip);
                        const key = try std.fmt.allocPrint(
                            self.allocator,
                            "{d}.{d}.{d}.{d}:{d}",
                            .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.dst_port },
                        );

                        log.info("join: key={s}", .{key});

                        self.members_mtx.lock();
                        self.members.put(key, .{ .state = .alive }) catch {};
                        self.members_mtx.unlock();
                    }
                },
                else => {
                    log.err("unsupported command: {any}", .{msg.cmd});
                },
            }
        }

        allocator: std.mem.Allocator,
        name: []u8 = undefined,
        ip: []u8 = undefined,
        port: u16 = 8080,
        protocol_time: u64 = std.time.ns_per_s * 2,
        ping_req_k: u32 = 1,
        mutex: std.Thread.Mutex = .{},
        members: std.StringHashMap(MemberData) = undefined,
        members_mtx: std.Thread.Mutex = .{},
        sweep: u1 = 1,
        incarnation: u64 = 0,

        // Main loop for initiating the SWIM protocol.
        fn tick(self: *Self) !void {
            var i: usize = 0;
            while (true) : (i += 1) {
                var skip = false;
                var tm = try std.time.Timer.start();
                self.members_mtx.lock();

                // Pre-check:
                // var iter = self.members.iterator();
                // while (iter.next()) |entry| {
                //     log.info("[{d}]tick1: {s}: key={s}, state={any}, sweep={d}, self_sweep={d}", .{
                //         i,
                //         self.name,
                //         entry.key_ptr.*,
                //         entry.value_ptr.state,
                //         entry.value_ptr.sweep,
                //         self.sweep,
                //     });
                // }

                var key: *[]const u8 = undefined;
                var found = false;
                var iter = self.members.iterator();
                while (iter.next()) |entry| {
                    if (entry.value_ptr.sweep != self.sweep) {
                        key = entry.key_ptr;
                        found = true;
                        break;
                    }
                }

                if (found) {
                    const ptr = self.members.getPtr(key.*).?;
                    ptr.sweep = ~ptr.sweep;
                    _ = self.ping(key) catch {};
                } else {
                    self.sweep = ~self.sweep;
                    skip = true;
                }

                // Post-check:
                // iter = self.members.iterator();
                // while (iter.next()) |entry| {
                //     log.info("[{d}]tick2: {s}: key={s}, state={any}, sweep={d}, self_sweep={d}", .{
                //         i,
                //         self.name,
                //         entry.key_ptr.*,
                //         entry.value_ptr.state,
                //         entry.value_ptr.sweep,
                //         self.sweep,
                //     });
                // }

                self.members_mtx.unlock();

                const elapsed = tm.read();
                if (elapsed < self.protocol_time and !skip) {
                    const left = self.protocol_time - elapsed;
                    log.info("tick: left={any}", .{std.fmt.fmtDuration(left)});
                    std.time.sleep(left);
                }
            }
        }

        // Run internal UDP server.
        fn listen(self: *Self) !void {
            log.info("Starting UDP server on :{any}...", .{self.port});
            defer log.info("listen done", .{});

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
                _ = try std.posix.recvfrom(
                    sock,
                    buf,
                    0,
                    &src_addr,
                    &src_addrlen,
                );

                var tm = try std.time.Timer.start();
                defer log.info("process took {any}", .{std.fmt.fmtDuration(tm.read())});

                var ack = true;
                const msg: *Message = @ptrCast(@alignCast(buf));

                switch (msg.cmd) {
                    .join => {
                        const hex = try std.fmt.parseUnsigned(u128, self.name, 0);
                        if (msg.name == hex) {
                            log.info("join: cmd={any}", .{msg.cmd});
                            log.info("join: name=0x{x}", .{msg.name});
                            log.info("join: src_ip={any}", .{msg.src_ip});
                            log.info("join: src_port={d}", .{msg.src_port});
                            log.info("join: dst_ip={any}", .{msg.dst_ip});
                            log.info("join: dst_port={d}", .{msg.dst_port});

                            const ipb = std.mem.asBytes(&msg.src_ip);
                            const key = try std.fmt.allocPrint(
                                self.allocator,
                                "{d}.{d}.{d}.{d}:{d}",
                                .{ ipb[0], ipb[1], ipb[2], ipb[3], msg.src_port },
                            );

                            log.info("join: key={s}", .{key});

                            self.members_mtx.lock();
                            self.members.put(key, .{ .state = .alive }) catch {};
                            self.members_mtx.unlock();
                        } else ack = false;
                    },
                    .ping => {
                        const hex = try std.fmt.parseUnsigned(u128, self.name, 0);
                        if (msg.name != hex) ack = false;
                    },
                    else => {
                        log.err("unsupported command: {any}", .{msg.cmd});
                        ack = false;
                    },
                }

                if (ack) {
                    msg.cmd = .ack;
                    _ = try std.posix.sendto(
                        sock,
                        std.mem.asBytes(msg),
                        0,
                        &src_addr,
                        src_addrlen,
                    );
                }
            }
        }

        fn ping(self: *Self, key: *[]const u8) !bool {
            var ip: []u8 = undefined;
            defer {
                if (ip.len > 0) self.allocator.free(ip);
            }

            var port: u16 = 0;
            var it = std.mem.split(u8, key.*, ":");
            if (it.next()) |val| {
                ip = try std.fmt.allocPrint(self.allocator, "{s}", .{val});
            }

            if (it.next()) |val| {
                port = try std.fmt.parseUnsigned(u16, val, 10);
            }

            if (std.mem.eql(u8, ip, self.ip) and port == self.port) {
                return false;
            }

            // Start direct ping.
            log.info("ping: {s}:{d}", .{ ip, port });

            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer
            const msg: *Message = @ptrCast(@alignCast(buf));
            msg.cmd = .ping;
            msg.name = try std.fmt.parseUnsigned(u128, self.name, 0);
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
            const len = try std.posix.recv(sock, buf, 0);

            switch (msg.cmd) {
                .ack => {
                    log.info("{d}: ack from {s}:{d}", .{ len, ip, port });
                },
                else => {
                    log.err("todo: ping-req", .{});
                },
            }

            return true;
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
