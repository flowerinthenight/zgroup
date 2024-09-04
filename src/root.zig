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

        pub fn init(allocator: std.mem.Allocator) !Self {
            return Self{
                .allocator = allocator,
                .members = std.StringHashMap(MemberData).init(allocator),
            };
        }

        pub fn run(self: *Self) !void {
            self.mutex.lock();
            try self.members.put("0.0.0.0", MemberData{ .state = .alive });
            self.mutex.unlock();

            const server = try std.Thread.spawn(.{}, Self.listen, .{self});
            server.detach();
            const ticker = try std.Thread.spawn(.{}, Self.tick, .{self});
            ticker.detach();
        }

        pub fn stop(self: *Self) void {
            log.info("stop:", .{});
            _ = @atomicRmw(
                u64,
                &self.incarnation,
                AtomicRmwOp.Add,
                1,
                AtomicOrder.seq_cst,
            );
        }

        allocator: std.mem.Allocator,
        name: []const u8 = "zgroup",
        port: u16 = 8080,
        protocol_time: u64 = std.time.ns_per_s * 2,
        mutex: std.Thread.Mutex = .{},
        members: std.StringHashMap(MemberData) = undefined,
        incarnation: u64 = 0,

        fn tick(self: *Self) !void {
            while (true) {
                var tm = try std.time.Timer.start();
                self.mutex.lock();
                var iter = self.members.iterator();
                while (iter.next()) |entry| {
                    log.info("key={s}, value={any}", .{
                        entry.key_ptr.*,
                        entry.value_ptr.state,
                    });
                }
                self.mutex.unlock();
                const elapsed = tm.read();
                if (elapsed < self.protocol_time) {
                    const left = self.protocol_time - elapsed;
                    log.info("left={any}", .{left});
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
                msg.cmd = .dummy;
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

/// Copied from zig-network:
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

/// Copied from zig-network:
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
