const std = @import("std");
const builtin = std.builtin;
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const backoff = @import("zbackoff");
const root = @import("root.zig");
const dbg = std.debug.print;

const log = std.log;

pub const std_options = .{
    .log_level = .info,
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .zgroup, .level = .info },
    },
};

const Args = struct {
    val: []const u8 = undefined,
};

pub fn main() !void {
    const bo = backoff.Backoff{};
    log.info("val={any}", .{bo.initial});

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
        log.info("val={s}", .{v.val});
    }

    var grp = try root.Group().init(gpa.allocator());
    try grp.run();
    std.time.sleep(10e9);
    grp.stop();
    std.time.sleep(10e9);
}

test "backoff" {
    const bo = backoff.Backoff{};
    dbg("val={any}\n", .{bo.initial});

    var alist = std.ArrayList(Args).init(std.testing.allocator);
    defer alist.deinit();

    try alist.append(.{ .val = "one" });
    try alist.append(.{ .val = "two" });
    try alist.append(.{ .val = "three" });
    try alist.append(.{ .val = "four" });

    for (alist.items, 0..) |v, i| {
        dbg("[{d}]val={s}\n", .{ i, v.val });
    } else {
        dbg("else items\n", .{});
    }

    dbg("val[2]={s}\n", .{alist.items[2].val});

    const ms = std.time.milliTimestamp();
    dbg("time={any}\n", .{ms});
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
    dbg("took {d}\n", .{tm.read()});
}

test "ip1" {
    const addr = try std.net.Address.resolveIp("127.0.0.1", 8080);
    dbg("0x{X}, {d}\n", .{ addr.in.sa.addr, addr.in.sa.addr });
}
