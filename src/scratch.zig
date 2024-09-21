const std = @import("std");
const builtin = std.builtin;
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const backoff = @import("zbackoff");
const zgroup = @import("zgroup.zig");
const dbg = std.debug.print;

const pdata = struct {
    ev1: *std.Thread.ResetEvent,
    ev2: *std.Thread.ResetEvent,
};

fn waiter(p: *pdata) void {
    for (0..2) |i| {
        dbg("{d} start wait1\n", .{i});
        p.ev1.wait();
        dbg("{d} end wait1, call reset\n", .{i});
        p.ev1.reset();

        dbg("{d} start wait2\n", .{i});
        p.ev2.wait();
        dbg("{d} end wait2, call reset\n", .{i});
        p.ev2.reset();
    }
}

fn testWaiter() !void {
    var ev1 = std.Thread.ResetEvent{};
    var ev2 = std.Thread.ResetEvent{};
    var data = pdata{ .ev1 = &ev1, .ev2 = &ev2 };

    const t = try std.Thread.spawn(.{}, waiter, .{&data});
    t.detach();

    std.time.sleep(std.time.ns_per_s * 5);
    ev1.set();
    ev2.set();
    std.time.sleep(std.time.ns_per_s * 5);
    ev1.set();
    ev2.set();
    std.time.sleep(std.time.ns_per_s * 5);
}

test "backoff" {
    // Try referencing external dep in test block.
    const bo = backoff.Backoff{};
    dbg("val={any}\n", .{bo.initial});
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
    dbg("took {any}\n", .{std.fmt.fmtDuration(tm.read())});
}

test "block" {
    const flag = false;
    section: {
        if (flag) {
            dbg("early return\n", .{});
            break :section;
        }

        dbg("final return\n", .{});
    }
}

test "tuple" {
    var tuple: std.meta.Tuple(&.{ u32, bool }) = .{ 100, true };
    dbg("{any}\n", .{tuple.len});
    tuple[0] = 200;
    dbg("{any}, {d}\n", .{ tuple.len, tuple[0] });
}

test "dupe" {
    const alloc = std.testing.allocator;
    const m1 = try std.fmt.allocPrint(alloc, "zig is the man", .{});
    defer alloc.free(m1);
    const dup1 = try alloc.dupe(u8, m1);
    defer alloc.free(dup1);
    const dup2 = try alloc.dupe(u8, m1);
    defer alloc.free(dup2);
    dbg("{s},{d}\n", .{ dup1, dup1.len });
    dbg("{s},{d}\n", .{ dup2, dup2.len });
}

test "view" {
    const en = enum(u4) {
        change,
        do,
        start,
    };

    const e: en = .start;
    dbg("size={d}\n", .{@sizeOf(@TypeOf(e))});
    const ee: en = @enumFromInt(2);
    dbg("int={any}\n", .{ee});

    const val = 17293822569102704642; // 2
    dbg("cmd={x}\n", .{(val & 0xf000000000000000) >> 60});
    dbg("val={x}\n", .{val & 0x0fffffffffffffff});
    dbg("{x}\n", .{0xffffffffffffffff & (0b11 << 62)});
}
