const std = @import("std");

pub fn main() !void {
    const port = 8080;
    std.debug.print("Connecting to :{any}...\n", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(sock);

    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(sock, "hello from client\n");
    _ = try std.posix.write(sock, "quit\n");
}
