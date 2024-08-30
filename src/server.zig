const std = @import("std");

pub fn main() !void {
    const port = 8080;
    std.debug.print("Starting UDP server on :{any}...\n", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    var buf: [1024]u8 = undefined;

    while (true) {
        const len = try std.posix.recv(sock, &buf, 0);
        std.debug.print("{d}: {s}", .{ len, buf[0..len] });
        if (std.mem.eql(u8, buf[0 .. len - 1], "quit")) {
            break;
        }
    }
}
