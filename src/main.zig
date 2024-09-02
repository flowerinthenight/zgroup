const std = @import("std");
const backoff = @import("zbackoff");
const builtin = std.builtin;
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const print = std.debug.print;

pub const Payload = packed struct {
    id: u64 = 2,
    name: u128 = 0,
    pos: i64 = -1,
    primary: bool = false,
};

const Args = struct {
    val: []const u8 = undefined,
};

pub fn main() !void {
    const bo = backoff.Backoff{};
    print("val={any}\n", .{bo.initial});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit(); // destroy arena in one go
    const allocator = arena.allocator();
    var args = try std.process.argsWithAllocator(allocator);
    var alist = std.ArrayList(Args).init(allocator);
    while (args.next()) |v| {
        try alist.append(.{ .val = v });
    }

    for (alist.items) |v| {
        print("val={s}\n", .{v.val});
    }
}

test "backoff" {
    const bo = backoff.Backoff{};
    print("val={any}\n", .{bo.initial});

    var alist = std.ArrayList(Args).init(std.testing.allocator);
    defer alist.deinit();

    try alist.append(.{ .val = "one" });
    try alist.append(.{ .val = "two" });
    try alist.append(.{ .val = "three" });
    try alist.append(.{ .val = "four" });

    for (alist.items, 0..) |v, i| {
        print("[{d}]val={s}\n", .{ i, v.val });
    } else {
        print("else items\n", .{});
    }

    print("val[2]={s}\n", .{alist.items[2].val});

    const ms = std.time.milliTimestamp();
    print("time={any}\n", .{ms});
}

test "atomic" {
    var tm = try std.time.Timer.start();
    var v: u64 = 0;
    @atomicStore(u64, &v, 1, AtomicOrder.seq_cst);
    _ = @atomicLoad(u64, &v, AtomicOrder.seq_cst);
    // print("load={d}\n", .{a});
    _ = @atomicRmw(u64, &v, AtomicRmwOp.Add, 1e9, AtomicOrder.seq_cst);
    _ = @atomicLoad(u64, &v, AtomicOrder.seq_cst);
    // print("add={d}\n", .{b});
    print("took {d}\n", .{tm.read()});
}
