const std = @import("std");
const dbg = std.debug.print;
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
        };

        pub const Config = struct {
            name: []u8 = undefined, // fmt: hex, i.e. 0xfff...
            addr: []u8 = undefined, // fmt: ipaddr, i.e. 0.0.0.0
            port: u16 = 0, // i.e. 8080
        };

        pub fn init(allocator: std.mem.Allocator, config: *const Config) !Self {
            return Self{
                .allocator = allocator,
                .name = config.name,
                .ipaddr = config.addr,
                .port = config.port,
                .members = std.StringHashMap(MemberData).init(allocator),
            };
        }

        pub fn run(self: *Self) !void {
            const key = try std.fmt.allocPrint(
                self.allocator,
                "{s}:{d}",
                .{ self.ipaddr, self.port },
            );

            try self.members.put(key, .{ .state = .alive });
            const server = try std.Thread.spawn(.{}, Self.listen, .{self});
            server.detach();
            const ticker = try std.Thread.spawn(.{}, Self.tick, .{self});
            ticker.detach();
        }

        pub fn deinit(self: *Self) void {
            // TODO:
            // 1. Free keys in members.
            // 2. Release members.
            // 3. See how to gracefuly exit threads.

            log.info("deinit:", .{});

            _ = @atomicRmw(
                u64,
                &self.incarnation,
                AtomicRmwOp.Add,
                1,
                AtomicOrder.seq_cst,
            );
        }

        /// Expected name is UUID string in hex, i.e. "0xf47ac10b58cc4372a5670e02b2c3d479".
        pub fn join(
            self: *Self,
            name: []const u8,
            src_ip: []const u8,
            src_port: u16,
            dst_ip: []const u8,
            dst_port: u16,
        ) !void {
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

            const msg: *Message = @ptrCast(@alignCast(buf));
            msg.cmd = Command.join;
            msg.name = try std.fmt.parseUnsigned(u128, name, 0);

            log.info("joining through {s}:{any}/{s}...", .{ dst_ip, dst_port, name });

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
            try setReadTimeout(sock, 1_000_000);
            try setWriteTimeout(sock, 1_000_000);

            try std.posix.connect(sock, &dst_addr.any, dst_addr.getOsSockLen());
            _ = try std.posix.write(sock, std.mem.asBytes(msg));
            const len = try std.posix.recv(sock, buf, 0);
            log.info("{d}: reply: cmd={any}, name=0x{x}", .{ len, msg.cmd, msg.name });
        }

        allocator: std.mem.Allocator,
        name: []u8 = undefined,
        ipaddr: []u8 = undefined,
        port: u16 = 8080,
        protocol_time: u64 = std.time.ns_per_s * 2,
        mutex: std.Thread.Mutex = .{},
        members: std.StringHashMap(MemberData) = undefined,
        members_mtx: std.Thread.Mutex = .{},
        incarnation: u64 = 0,

        fn tick(self: *Self) !void {
            while (true) {
                var tm = try std.time.Timer.start();
                self.members_mtx.lock();
                var iter = self.members.iterator();
                while (iter.next()) |entry| {
                    log.info("tick: {s}: key={s}, value={any}", .{
                        self.name,
                        entry.key_ptr.*,
                        entry.value_ptr.state,
                    });
                }

                self.members_mtx.unlock();
                const elapsed = tm.read();
                if (elapsed < self.protocol_time) {
                    const left = self.protocol_time - elapsed;
                    log.info("tick: left={any}", .{std.fmt.fmtDuration(left)});
                    std.time.sleep(left);
                }
            }
        }

        fn listen(self: *Self) !void {
            defer log.info("listen done", .{});
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

            log.info("Starting UDP server on :{any}...", .{self.port});
            const addr = try std.net.Address.resolveIp("0.0.0.0", self.port);
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM,
                std.posix.IPPROTO.UDP,
            );

            defer std.posix.close(sock);
            try setWriteTimeout(sock, 1_000_000);
            try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
            var src_addr: std.os.linux.sockaddr = undefined;
            var src_addrlen: std.posix.socklen_t = @sizeOf(std.os.linux.sockaddr);

            while (true) {
                const len = try std.posix.recvfrom(
                    sock,
                    buf,
                    0,
                    &src_addr,
                    &src_addrlen,
                );

                var tm = try std.time.Timer.start();
                defer log.info("took {any}us", .{tm.read() / std.time.ns_per_us});

                const msg: *Message = @ptrCast(@alignCast(buf));
                log.info("{d}: cmd={any}, name=0x{x}", .{ len, msg.cmd, msg.name });

                switch (msg.cmd) {
                    Command.join => {
                        log.info("join: cmd={any}", .{msg.cmd});
                        log.info("join: name=0x{x}", .{msg.name});
                        log.info("join: src_ip={any}", .{msg.src_ip});
                        log.info("join: src_port={d}", .{msg.src_port});
                        log.info("join: dst_ip={any}", .{msg.dst_ip});
                        log.info("join: dst_port={d}", .{msg.dst_port});
                    },
                    else => {
                        log.err("unsupported command: {any}", .{msg.cmd});
                    },
                }

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
