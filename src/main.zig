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
    args: []u8 = undefined,
};

pub fn main() !void {
    const bo = backoff.Backoff{};
    log.info("val={any}", .{bo.initial});

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
    // [2] = member addr:port
    // [3] = join addr:port

    var iter = hm.iterator();
    while (iter.next()) |entry| {
        log.info("{any}, {s}", .{ entry.key_ptr.*, entry.value_ptr.args });
    }

    if (hm.count() < 4) {
        log.err("invalid args", .{});
        return;
    }

    var config = root.Group().Config{ .name = hm.getEntry(1).?.value_ptr.args };
    var it = std.mem.split(u8, hm.getEntry(2).?.value_ptr.args, ":");
    if (it.next()) |val| {
        config.ip = try std.fmt.allocPrint(arena.allocator(), "{s}", .{val});
    }

    if (it.next()) |val| {
        config.port = try std.fmt.parseUnsigned(u16, val, 10);
    }

    var dst_ip: []u8 = undefined;
    it = std.mem.split(u8, hm.getEntry(3).?.value_ptr.args, ":");
    if (it.next()) |val| {
        dst_ip = try std.fmt.allocPrint(arena.allocator(), "{s}", .{val});
    }

    var dst_port: u16 = 0;
    if (it.next()) |val| {
        if (val.len > 0) {
            dst_port = try std.fmt.parseUnsigned(u16, val, 10);
        }
    }

    var grp = try root.Group().init(gpa.allocator(), &config);
    try grp.run();
    defer grp.deinit();

    i = 0; // reuse
    while (true) : (i += 1) {
        std.time.sleep(std.time.ns_per_s * 1);
        if (i == 10 and dst_ip.len > 0) {
            try grp.join(
                hm.getEntry(1).?.value_ptr.args,
                config.ip,
                config.port,
                dst_ip,
                dst_port,
            );
        }
    }
}

test "autohashmap" {
    const Value = struct {
        id: u32 = 0,
    };

    var hm = std.AutoHashMap(usize, Value).init(std.testing.allocator);
    defer hm.deinit();
    try hm.put(hm.count(), .{ .id = 100 });
    try hm.put(hm.count(), .{ .id = 101 });

    const ptr = hm.getPtr(1).?;
    ptr.* = .{ .id = 201 };

    var iter = hm.iterator();
    while (iter.next()) |entry| {
        dbg("{any}, {d}\n", .{ entry.key_ptr.*, entry.value_ptr.id });
    }
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
    dbg("took {any}\n", .{std.fmt.fmtDuration(tm.read())});
}

test "ip1" {
    const addr = try std.net.Address.resolveIp("127.0.0.1", 8080);
    const ab = std.mem.asBytes(&addr.in.sa.addr);
    dbg("0x{X}, {d}, {any}\n", .{ addr.in.sa.addr, addr.in.sa.addr, ab });
    dbg("{d}.{d}.{d}.{d}\n", .{ ab[0], ab[1], ab[2], ab[3] });
}
