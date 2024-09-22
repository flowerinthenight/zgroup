const std = @import("std");
const backoff = @import("zbackoff");
const zgroup = @import("zgroup.zig");

const log = std.log;

pub const std_options = .{
    .log_level = .info,
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .zgroup, .level = .debug },
    },
};

const UserData = struct {
    group: []const u8,
    skip_callback: bool = false,
};

// We are using curl here as std.http.Client seems to not play well with this endpoint.
// The "seegmed7" in the url is our API key. The allocator here is the allocator passed
// to Fleet's init function. `addr`'s format is "ip:port", e.g. "127.0.0.1:8080", and
// needs to be freed after use.
fn callback(allocator: std.mem.Allocator, data: ?*UserData, addr: []const u8) !void {
    defer allocator.free(addr);
    if (data.?.skip_callback) return;

    const enc = std.base64.Base64Encoder.init(std.base64.url_safe_alphabet_chars, '=');
    const buf = try allocator.alloc(u8, enc.calcSize(addr.len));
    defer allocator.free(buf);
    const out = enc.encode(buf, addr);

    log.info("callback: leader={s}, set join info to {s}", .{ addr, out });

    const url = try std.fmt.allocPrint(
        allocator,
        "https://keyvalue.immanuel.co/api/KeyVal/UpdateValue/seegmed7/{s}/{s}",
        .{ data.?.group, out },
    );

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl",
            "-X",
            "POST",
            "-H",
            "Content-Length: 1", // somehow, this works with this endpoint (required though)
            url,
        },
    });

    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }
}

const Fleet = zgroup.Fleet(UserData);

// Expected cmdline args:
//
//   [0] = bin
//   [1] = name
//   [2] = member ip:port
//   [3] = join ip:port (optional)
//
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit(); // destroy arena in one go

    var args = try std.process.argsWithAllocator(arena.allocator());
    var hm = std.AutoHashMap(usize, []const u8).init(arena.allocator());
    var i: usize = 0;
    while (args.next()) |val| : (i += 1) {
        const arg = try std.fmt.allocPrint(arena.allocator(), "{s}", .{val});
        try hm.put(i, arg);
    }

    if (hm.count() < 3) {
        log.err("invalid args", .{});
        return;
    }

    var iter = hm.iterator();
    while (iter.next()) |entry| {
        log.info("{any}, {s}", .{ entry.key_ptr.*, entry.value_ptr.* });
    }

    const name = hm.getEntry(1).?.value_ptr.*;

    var data = UserData{ .group = name };
    const callbacks = Fleet.Callbacks{
        .data = &data,
        .onLeader = callback,
        .on_leader_every = 10,
    };

    var member = hm.getEntry(2).?.value_ptr.*;
    var sep = std.mem.indexOf(u8, member, ":").?;

    // This sample sets both protocol time and suspicion time to 2s.
    var config = Fleet.Config{
        .name = name,
        .ip = member[0..sep],
        .callbacks = callbacks,
    };

    config.port = try std.fmt.parseUnsigned(u16, member[sep + 1 ..], 10);

    var fleet = try Fleet.init(gpa.allocator(), &config);
    try fleet.run();
    defer fleet.deinit();

    i = 0;
    var bo = backoff.Backoff{};
    while (true) : (i += 1) {
        std.time.sleep(std.time.ns_per_s * 1);

        // Delay for a bit before joining group.
        if (i == 2) {
            switch (hm.count()) {
                3 => {
                    // No join address in args. Try using a free discovery service.
                    var join_addr: []const u8 = "";
                    for (0..10) |_| {
                        const ja = try getJoinAddress(arena.allocator(), name);
                        if (ja.len > 0) {
                            join_addr = ja;
                            break;
                        } else std.time.sleep(bo.pause());
                    }

                    log.info("join address found, addr={s}", .{join_addr});

                    sep = std.mem.indexOf(u8, join_addr, ":").?;
                    const join_ip = join_addr[0..sep];
                    if (join_ip.len == 0) {
                        log.err("invalid join address", .{});
                        return;
                    }

                    var join_port: u16 = 0;
                    if (join_addr[sep + 1 ..].len > 0) {
                        join_port = try std.fmt.parseUnsigned(u16, join_addr[sep + 1 ..], 10);
                    }

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
                },
                4 => {
                    // Join address is provided. Skip callback.
                    data.skip_callback = true;

                    const join = hm.getEntry(3).?.value_ptr.*;
                    sep = std.mem.indexOf(u8, join, ":").?;
                    const join_ip = join[0..sep];
                    if (join_ip.len == 0) {
                        log.err("invalid join address", .{});
                        return;
                    }

                    var join_port: u16 = 0;
                    if (join[sep + 1 ..].len > 0) {
                        join_port = try std.fmt.parseUnsigned(u16, join[sep + 1 ..], 10);
                    }

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
                },
                else => {},
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

// We are using curl here as std.http.Client seems to not play well with this endpoint.
// The "seegmed7" in the url is our API key. We are passing an arena allocator here.
fn getJoinAddress(allocator: std.mem.Allocator, group: []const u8) ![]u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "https://keyvalue.immanuel.co/api/KeyVal/GetValue/seegmed7/{s}",
        .{group},
    );

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "curl", url },
    });

    const out = std.mem.trim(u8, result.stdout, "\"");
    const dec = std.base64.Base64Decoder.init(std.base64.url_safe_alphabet_chars, '=');
    const buf = try allocator.alloc(u8, try dec.calcSizeUpperBound(out.len));
    try dec.decode(buf, out);
    return buf;
}
