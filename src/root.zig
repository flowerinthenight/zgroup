const std = @import("std");
const dbg = std.debug.print;

const log = std.log.scoped(.zgroup);

pub const UdpServer = struct {
    allocator: std.mem.Allocator,
    list: std.ArrayList(u64) = undefined,
    const Self = @This();

    pub fn run(self: *Self) void {
        log.info("init:", .{});
        self.list = std.ArrayList(u64).init(self.allocator);
    }

    pub fn add(self: *Self) !void {
        log.info("add:", .{});
        try self.list.append(22);
        for (self.list.items) |v| {
            log.info("item={any}", .{v});
        }
    }

    pub fn stop(self: *Self) void {
        log.info("deinit:", .{});
        self.list.deinit();
    }

};

const Node = struct {
    allocator: std.mem.Allocator,
    self: @This(),
    incarnation: u64 = 0,
};


/// Copied from zig-network:
/// Set socket read timeout in microseconds. Linux only.
pub fn setReadTimeout(socket: std.posix.socket_t, read: ?u32) !void {
    std.debug.assert(read == null or read.? != 0);
    const micros = read orelse 0;
    const opt =  std.posix.timeval{
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
    const opt =  std.posix.timeval{
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

const Sample = packed struct {
    id: u64 = 2,
    pos: i64 = -1,
    main: bool = false,
    name: u128 = 0,
};

test "timer" {
    var tm = try std.time.Timer.start();
    dbg("v={any}\n", .{tm.read()});
    std.time.sleep(std.time.ns_per_ms * 1000);
    dbg("v={any}\n", .{tm.read()});
    std.time.sleep(1e9);
    dbg("v={any}\n", .{tm.lap()});
    std.time.sleep(1e9);
    dbg("v={any}\n", .{tm.lap()});
}
