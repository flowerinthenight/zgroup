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
    args: []u8 = undefined,
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

    var config = zgroup.Fleet().Config{ .name = hm.getEntry(1).?.value_ptr.args };
    const member = hm.getEntry(2).?.value_ptr.args;
    var split = std.mem.indexOf(u8, member, ":").?;
    config.ip = member[0..split];
    config.port = try std.fmt.parseUnsigned(u16, member[split + 1 ..], 10);

    const join = hm.getEntry(3).?.value_ptr.args;
    split = std.mem.indexOf(u8, join, ":").?;
    const join_ip = join[0..split];
    var join_port: u16 = 0;
    if (join[split + 1 ..].len > 0) {
        join_port = try std.fmt.parseUnsigned(u16, join[split + 1 ..], 10);
    }

    var grp = try zgroup.Fleet().init(gpa.allocator(), &config);
    try grp.run();
    defer grp.deinit();

    i = 0; // reuse
    var bo = backoff.Backoff{};
    while (true) : (i += 1) {
        std.time.sleep(std.time.ns_per_s * 1);
        if (i == 2 and join_ip.len > 0) {
            var joined = false;
            for (0..3) |_| {
                try grp.join(
                    hm.getEntry(1).?.value_ptr.args,
                    config.ip,
                    config.port,
                    join_ip,
                    join_port,
                    &joined,
                );

                if (joined) break else std.time.sleep(bo.pause());
            }
        }
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
