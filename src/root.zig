const std = @import("std");
const print = std.debug.print;

const Sample = packed struct {
    id: u64 = 1,
    pos: i64 = -1,
    main: bool = false,
};

test "gen" {
    const n = @sizeOf(Sample);
    print("size={any}\n", .{n});
    const tmp = Sample{
        .main = true,
    };
    const b = std.mem.asBytes(&tmp);
    print("bytes={any}, ptr={any}, len={any}\n", .{ b, b.ptr, b.len });

    const ptr: *Sample = @ptrFromInt(@intFromPtr(b));
    print("id={any}, pos={any}, main={any}\n", .{ ptr.id, ptr.pos, ptr.main });
}
