const std = @import("std");
const backoff = @import("zbackoff");

const Args = struct {
    val: []const u8 = undefined,
};

pub fn main() !void {
    const bo = backoff.Backoff{};
    std.debug.print("val={any}\n", .{bo.initial});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit(); // destroy arena one time
    const arena_alloc = arena.allocator();
    var args = try std.process.argsWithAllocator(arena_alloc);
    // defer args.deinit();

    var alist = std.ArrayList(Args).init(arena_alloc);
    // defer alist.deinit();

    while (args.next()) |v| {
        try alist.append(.{ .val = v });
    }

    for (alist.items) |v| {
        std.debug.print("val={s}\n", .{v.val});
    }
}

test "backoff" {
    const bo = backoff.Backoff{};
    std.debug.print("val={any}\n", .{bo.initial});

    var alist = std.ArrayList(Args).init(std.testing.allocator);
    defer alist.deinit();

    try alist.append(.{ .val = "one" });
    try alist.append(.{ .val = "two" });
    try alist.append(.{ .val = "three" });
    try alist.append(.{ .val = "four" });

    for (alist.items) |v| {
        std.debug.print("val={s}\n", .{v.val});
    }

    std.debug.print("val[2]={s}\n", .{alist.items[2].val});
}
