const std = @import("std");
const print = std.debug.print;

const Sample = packed struct {
    id: u64 = 2,
    pos: i64 = -1,
    main: bool = false,
    name: u128 = 0,
};

test "gen" {
    const n = @sizeOf(Sample);
    print("size={any}\n", .{n});

    const hex = "0xf47ac10b58cc4372a5670e02b2c3d479";
    const name = std.fmt.parseUnsigned(u128, hex, 0) catch return;
    const tmp = Sample{
        .main = true,
        .name = name,
    };

    const b = std.mem.asBytes(&tmp);
    print("bytes={any}, ptr={any}, len={any}\n", .{ b, b.ptr, b.len });

    const ptr: *Sample = @ptrFromInt(@intFromPtr(b));
    print("id={any}, pos={any}, main={any}\n", .{ ptr.id, ptr.pos, ptr.main });

    print("name=0x{x}\n", .{ptr.name});
}
