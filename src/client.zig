const std = @import("std");
const Payload = @import("main.zig").Payload;

pub fn main() !void {
    const hex = "0xf47ac10b58cc4372a5670e02b2c3d479";
    const name = try std.fmt.parseUnsigned(u128, hex, 0);
    var pl = Payload{
        .name = name,
        .primary = true,
    };

    const port = 8080;
    std.debug.print("Connecting to :{any}...\n", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(sock);

    var buf: [1024]u8 = undefined;
    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(sock, std.mem.asBytes(&pl));
    var len = try std.posix.recv(sock, &buf, 0);
    std.debug.print("reply: {s}\n", .{buf[0..len]});

    pl.id = 0; // quit
    _ = try std.posix.write(sock, std.mem.asBytes(&pl));
    len = try std.posix.recv(sock, &buf, 0);
    std.debug.print("reply: {s}\n", .{buf[0..len]});
}
