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

    const port = 8080;
    log.info("Starting UDP server on :{any}...", .{port});
    const addr = try std.net.Address.resolveIp("0.0.0.0", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    try root.setWriteTimeout(sock, 1_000_000);
    try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    var src_addr: std.os.linux.sockaddr = undefined;
    var src_addrlen: std.posix.socklen_t = @sizeOf(std.os.linux.sockaddr);

    while (true) {
        const len = try std.posix.recvfrom(sock, buf, 0, &src_addr, &src_addrlen);
        const ptr: *Group.Message = @ptrCast(@alignCast(buf));
        log.info("{d}: cmd={any}, name=0x{x}", .{ len, ptr.cmd, ptr.name });
        const cmd = ptr.cmd;
        _ = try std.posix.sendto(sock, std.mem.asBytes(ptr), 0, &src_addr, src_addrlen);
        if (cmd == Group.Command.exit) {
            break;
        }
    }
}
