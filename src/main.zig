const std = @import("std");
const backoff = @import("zbackoff");

pub fn main() !void {
    const bo = backoff.Backoff{};
    std.debug.print("val={any}.\n", .{bo.initial});
}

test "backoff" {
    const bo = backoff.Backoff{};
    std.debug.print("val={any}\n", .{bo.initial});
}
