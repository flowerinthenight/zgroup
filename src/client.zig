const std = @import("std");
const print = std.debug.print;
const root = @import("root.zig");
const Group = @import("root.zig").Group();

const log = std.log;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const buf = try allocator.alloc(u8, @sizeOf(Group.Message));
    defer allocator.free(buf); // release buffer

    const ptr: *Group.Message = @ptrCast(@alignCast(buf));
    const hex = "0xf47ac10b58cc4372a5670e02b2c3d479";
    ptr.cmd = Group.Command.ack; // default
    ptr.name = try std.fmt.parseUnsigned(u128, hex, 0);

    const port = 8080;
    log.info("Connecting to :{any}...", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(sock);
    try root.setReadTimeout(sock, 1_000_000);
    try root.setWriteTimeout(sock, 1_000_000);

    var len: usize = undefined;
    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(sock, std.mem.asBytes(ptr));
    len = try std.posix.recv(sock, buf, 0);
    log.info("{d}: reply: cmd={any}, name=0x{x}", .{ len, ptr.cmd, ptr.name });

    ptr.cmd = Group.Command.exit;
    _ = try std.posix.write(sock, std.mem.asBytes(ptr));
    len = try std.posix.recv(sock, buf, 0);
    log.info("{d}: reply: cmd={any}, name=0x{x}", .{ len, ptr.cmd, ptr.name });
}
