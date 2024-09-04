const std = @import("std");
const dbg = std.debug.print;
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;

const log = std.log.scoped(.zgroup);

pub const Message = packed struct {
    id: u64 = 2,
    name: u128 = 0,
    pos: i64 = -1,
    primary: bool = false,
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    name: []const u8 = "zgroup",
    incarnation: u64 = 0,

    const Self = @This();

    pub fn run(self: *Self) !void {
        log.info("run: name={s}", .{self.name});
        const server = try std.Thread.spawn(.{}, Self.listenUdp, .{self});
        server.detach();
    }

    pub fn listenUdp(self: *Self) void {
        defer log.info("listenUdp done", .{});
        while (true) {
            log.info("incarnation={d}", .{self.incarnation});
            std.time.sleep(3e9);
            const v = @atomicLoad(u64, &self.incarnation, AtomicOrder.seq_cst);
            if (v > 0) {
                break;
            }
        }
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
};

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
