const std = @import("std");
const testing = std.testing;

const Sample = packed struct {
    id: u64 = 1,
    pos: i64 = -1,
};

test "gen" {
    const n = @sizeOf(Sample);
    std.debug.print("size={d}\n", .{n});
    const tmp = Sample{};
    const b = std.mem.asBytes(&tmp);
    std.debug.print("bytes={any}, ptr={any}, len={any}\n", .{ b, b.ptr, b.len });

    const ptr = @intFromPtr(b);
    std.debug.print("back={any}\n", .{ptr});
    const back: *Sample = @ptrFromInt(ptr);
    std.debug.print("id={any}, pos={any}\n", .{ back.id, back.pos });
}
