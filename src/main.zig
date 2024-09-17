const std = @import("std");
const builtin = std.builtin;
const AtomicOrder = std.builtin.AtomicOrder;
const AtomicRmwOp = std.builtin.AtomicRmwOp;
const backoff = @import("zbackoff");
const zgroup = @import("zgroup.zig");
const dbg = std.debug.print;

const log = std.log;

pub const std_options = .{
    .log_level = .info,
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .zgroup, .level = .debug },
    },
};

const Args = struct {
    args: []u8,
};

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

pub fn main() !void {
    // if (true) {
    //     var ev1 = std.Thread.ResetEvent{};
    //     var ev2 = std.Thread.ResetEvent{};
    //     var data = pdata{ .ev1 = &ev1, .ev2 = &ev2 };

    //     const t = try std.Thread.spawn(.{}, waiter, .{&data});
    //     t.detach();

    //     std.time.sleep(std.time.ns_per_s * 5);
    //     ev1.set();
    //     ev2.set();
    //     std.time.sleep(std.time.ns_per_s * 5);
    //     ev1.set();
    //     ev2.set();
    //     std.time.sleep(std.time.ns_per_s * 5);
    //     return;
    // }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit(); // destroy arena in one go

    var args = try std.process.argsWithAllocator(arena.allocator());
    var hm = std.AutoHashMap(usize, Args).init(arena.allocator());
    var i: usize = 0;
    while (args.next()) |val| : (i += 1) {
        const key = try std.fmt.allocPrint(arena.allocator(), "{s}", .{val});
        try hm.put(i, .{ .args = key });
    }

    // Expected:
    // [0] = bin
    // [1] = name
    // [2] = member ip:port
    // [3] = join ip:port

    if (hm.count() < 4) {
        log.err("invalid args", .{});
        return;
    }

    var iter = hm.iterator();
    while (iter.next()) |entry| {
        log.info("{any}, {s}", .{ entry.key_ptr.*, entry.value_ptr.args });
    }

    const name = hm.getEntry(1).?.value_ptr.args;
    var member = hm.getEntry(2).?.value_ptr.args;
    var sep = std.mem.indexOf(u8, member, ":").?;
    var config = zgroup.Fleet().Config{ .name = name, .ip = member[0..sep] };
    config.port = try std.fmt.parseUnsigned(u16, member[sep + 1 ..], 10);

    const join = hm.getEntry(3).?.value_ptr.args;
    sep = std.mem.indexOf(u8, join, ":").?;
    const join_ip = join[0..sep];
    var join_port: u16 = 0;
    if (join[sep + 1 ..].len > 0) {
        join_port = try std.fmt.parseUnsigned(u16, join[sep + 1 ..], 10);
    }

    var fleet = try zgroup.Fleet().init(gpa.allocator(), &config);
    try fleet.run();
    defer fleet.deinit();

    i = 0;
    var bo = backoff.Backoff{};
    while (true) : (i += 1) {
        std.time.sleep(std.time.ns_per_s * 1);
        if (i == 2 and join_ip.len > 0) {
            for (0..3) |_| {
                var joined = false;
                fleet.join(
                    name,
                    join_ip,
                    join_port,
                    &joined,
                ) catch |err| log.err("join failed: {any}", .{err});

                if (joined) break else std.time.sleep(bo.pause());
            }
        }

        // if (i > 0 and @mod(i, 10) == 0) {
        //     const members = try fleet.memberNames(gpa.allocator());
        //     defer members.deinit();
        //     for (members.items, 0..) |v, j| {
        //         defer gpa.allocator().free(v);
        //         log.info("(from main) member[{d}]: {s}", .{ j, v });
        //     }
        // }
    }
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
