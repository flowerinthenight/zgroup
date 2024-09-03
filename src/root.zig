const std = @import("std");
const dbg = std.debug.print;

const log = std.log.scoped(.zgroup);

pub fn hello() void {
    log.info("hello", .{});
}

const Node = struct {
    allocator: std.mem.Allocator,
    self: @This(),
};

const Sample = packed struct {
    id: u64 = 2,
    pos: i64 = -1,
    main: bool = false,
    name: u128 = 0,
};

test "sample" {
    const n = @sizeOf(Sample);
    dbg("size={any}\n", .{n});

    const hex = "0xf47ac10b58cc4372a5670e02b2c3d479";
    const name = try std.fmt.parseUnsigned(u128, hex, 0);
    const tmp = Sample{
        .main = true,
        .name = name,
    };

    const b = std.mem.asBytes(&tmp);
    dbg("bytes={any}, ptr={any}, len={any}\n", .{ b, b.ptr, b.len });

    const ptr: *Sample = @ptrFromInt(@intFromPtr(b));
    dbg("id={any}, pos={any}, main={any}\n", .{ ptr.id, ptr.pos, ptr.main });

    dbg("name=0x{x}\n", .{ptr.name});
}

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
