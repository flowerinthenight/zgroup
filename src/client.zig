const std = @import("std");

pub fn main() !void {
    const port = 8080;
    std.debug.print("Connecting to :{any}...\n", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(sock);

    var buf: [1024]u8 = undefined;
    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(sock, "hello from client\n");
    const len = try std.posix.recv(sock, &buf, 0);
    std.debug.print("reply: {s}\n", .{buf[0..len]});

    _ = try std.posix.write(sock, "quit\n");
}
