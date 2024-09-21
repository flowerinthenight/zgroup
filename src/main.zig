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

const UserData = struct {
    dummy: u32,
};

fn callback(allocator: std.mem.Allocator, data: ?*UserData, addr: []const u8) !void {
    var tm = try std.time.Timer.start();
    defer {
        allocator.free(addr);
        log.info("callback took {any}", .{std.fmt.fmtDuration(tm.read())});
    }

    _ = data;
    log.info("callback: leader={s}", .{addr});
}

const Fleet = zgroup.Fleet(UserData);

// Expected cmdline args:
//
//   [0] = bin
//   [1] = name
//   [2] = member ip:port
//   [3] = join ip:port
//
pub fn main() !void {
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

    if (hm.count() < 4) {
        log.err("invalid args", .{});
        return;
    }

    var iter = hm.iterator();
    while (iter.next()) |entry| {
        log.info("{any}, {s}", .{ entry.key_ptr.*, entry.value_ptr.args });
    }

    var data = UserData{ .dummy = 10 };
    const callbacks = Fleet.Callbacks{
        .data = &data,
        .onLeader = callback,
        .on_leader_every = 10,
    };

    const name = hm.getEntry(1).?.value_ptr.args;
    var member = hm.getEntry(2).?.value_ptr.args;
    var sep = std.mem.indexOf(u8, member, ":").?;
    var config = Fleet.Config{ .name = name, .ip = member[0..sep], .callbacks = callbacks };
    config.port = try std.fmt.parseUnsigned(u16, member[sep + 1 ..], 10);

    const join = hm.getEntry(3).?.value_ptr.args;
    sep = std.mem.indexOf(u8, join, ":").?;
    const join_ip = join[0..sep];
    var join_port: u16 = 0;
    if (join[sep + 1 ..].len > 0) {
        join_port = try std.fmt.parseUnsigned(u16, join[sep + 1 ..], 10);
    }

    var fleet = try Fleet.init(gpa.allocator(), &config);
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

        // if (i > 0 and @mod(i, 5) == 0) b: {
        //     const ldr = try fleet.getLeader(gpa.allocator()) orelse break :b;
        //     defer gpa.allocator().free(ldr);
        //     log.info("--- leader={s}", .{ldr});
        // }

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
