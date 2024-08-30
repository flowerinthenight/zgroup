const std = @import("std");
const Payload = @import("main.zig").Payload;

pub fn main() !void {
    std.debug.print("size={any}, align={any}\n", .{ @sizeOf(Payload), @alignOf(Payload) });

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const buf = try allocator.alloc(u8, @sizeOf(Payload));
    defer allocator.free(buf); // release buffer

    const port = 8080;
    std.debug.print("Starting UDP server on :{any}...\n", .{port});
    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    var src_addr: std.os.linux.sockaddr = undefined;
    var src_addrlen: std.posix.socklen_t = @sizeOf(std.os.linux.sockaddr);

    while (true) {
        const len = try std.posix.recvfrom(sock, buf, 0, &src_addr, &src_addrlen);
        const ptr: *Payload = @ptrCast(@alignCast(buf));
        std.debug.print("{d}: id={d}, name=0x{x}\n", .{ len, ptr.id, ptr.name });
        const id = ptr.id;

        ptr.id = 10; // reply
        _ = std.posix.sendto(sock, std.mem.asBytes(ptr), 0, &src_addr, src_addrlen) catch |err| {
            std.debug.print("ack failed: {any}", .{err});
        };

        if (id == 0) {
            break;
        }
    }
}
