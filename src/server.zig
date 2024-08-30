const std = @import("std");

pub fn main() !void {
    const port = 8080;
    std.debug.print("Starting UDP server on :{any}...\n", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    var buf: [1024]u8 = undefined;
    var src_addr: std.os.linux.sockaddr = undefined;
    var src_addrlen: std.posix.socklen_t = @sizeOf(std.os.linux.sockaddr);

    while (true) {
        const len = try std.posix.recvfrom(sock, &buf, 0, &src_addr, &src_addrlen);
        std.debug.print("{d}: {s}", .{ len, buf[0..len] });
        if (std.mem.eql(u8, buf[0 .. len - 1], "quit")) {
            break;
        }

        _ = std.posix.sendto(sock, "ack", 0, &src_addr, src_addrlen) catch |err| {
            std.debug.print("ack failed: {any}", .{err});
        };
    }
}
