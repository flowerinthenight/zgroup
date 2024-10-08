const std = @import("std");
const zgroup = @import("zgroup.zig");
const backoff = @import("zbackoff");

const log = std.log;

// You can change zgroup's log-level to .info.
pub const std_options = .{
    .log_level = .info,
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .zgroup, .level = .debug },
    },
};

// To be passed to our callback(s).
const UserData = struct {
    prefix: []const u8,
    group: []const u8,
    skip_callback: bool = false,
};

const Fleet = zgroup.Fleet(UserData);

// A sample binary on how to use the zgroup library.
// Expected cmdline args:
//
//   [0] = bin
//   [1] = name
//   [2] = member ip:port
//   [3] = join ip:port (optional)
//
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var aa = std.heap.ArenaAllocator.init(gpa.allocator());
    defer aa.deinit(); // destroy arena in one go
    const arena = aa.allocator();

    // Collect process args to a map.
    var args = try std.process.argsWithAllocator(arena);
    var hm = std.AutoHashMap(usize, []const u8).init(arena);
    var i: usize = 0;
    while (args.next()) |val| : (i += 1) {
        const arg = try std.fmt.allocPrint(arena, "{s}", .{val});
        try hm.put(i, arg);
    }

    if (hm.count() < 3) {
        log.err("invalid args", .{});
        return;
    }

    var iter = hm.iterator();
    while (iter.next()) |v|
        log.info("args[{d}]: {s}", .{ v.key_ptr.*, v.value_ptr.* });

    // Required: so we can have our own unique URL in the free service.
    var envmap = try std.process.getEnvMap(arena);
    if (hm.count() == 3) {
        const jp = envmap.getPtr("ZGROUP_JOIN_PREFIX");
        if (jp) |_| {} else {
            log.err("no $ZGROUP_JOIN_PREFIX envvar found", .{});
            return;
        }
    }

    const name = hm.getEntry(1).?.value_ptr.*;

    var data = UserData{
        .prefix = b: {
            const jp = envmap.getPtr("ZGROUP_JOIN_PREFIX");
            if (jp) |v| break :b v.* else {
                break :b try std.fmt.allocPrint(arena, "", .{});
            }
        },
        .group = name,
    };

    const callbacks = Fleet.Callbacks{
        .data = &data, // arbitrary callback data

        // Callback function for the join address.
        .onJoinAddr = onJoinAddr,

        // So we won't overload the free service we are using.
        .on_join_every = 50,
    };

    var member = hm.getEntry(2).?.value_ptr.*;
    var sep = std.mem.indexOf(u8, member, ":").?;

    var cfg = Fleet.Config{
        .name = name,
        .ip = member[0..sep],
        .callbacks = callbacks,
    };

    cfg.port = try std.fmt.parseUnsigned(u16, member[sep + 1 ..], 10);

    var fleet = try Fleet.init(gpa.allocator(), &cfg);
    try fleet.run(); // actual run, join later
    defer fleet.deinit();

    i = 0;
    var joined = false;
    var bo = backoff.Backoff{};
    while (true) : (i += 1) {
        if (joined)
            std.time.sleep(std.time.ns_per_s * 1)
        else
            std.time.sleep(if (i >= 100) std.time.ns_per_s else bo.pause());

        if (i > 1 and i < 100 and !joined) {
            switch (hm.count()) {
                3 => {
                    // No join address in args. Try using a free discovery service.
                    var join_addr: []const u8 = "";
                    const ja = try getJoinAddress(
                        arena,
                        envmap.getPtr("ZGROUP_JOIN_PREFIX").?.*,
                        name,
                    );

                    if (ja.len > 0) join_addr = ja else continue;

                    log.info("[{d}] join address found, addr={s}", .{ i, join_addr });

                    sep = std.mem.indexOf(u8, join_addr, ":").?;
                    const join_port = try std.fmt.parseUnsigned(
                        u16,
                        join_addr[sep + 1 ..],
                        10,
                    );

                    fleet.join(
                        name,
                        join_addr[0..sep],
                        join_port,
                        &joined,
                    ) catch |err|
                        log.err("joining thru {s}:{d} failed: {any}", .{
                        join_addr[0..sep],
                        join_port,
                        err,
                    });
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

                    const join_port = try std.fmt.parseUnsigned(
                        u16,
                        join[sep + 1 ..],
                        10,
                    );

                    fleet.join(
                        name,
                        join_ip,
                        join_port,
                        &joined,
                    ) catch |err| log.err("join failed: {any}", .{err});
                },
                else => {},
            }
        }

        // Sample code on getting the current members in the group.
        if (i > 0 and @mod(i, 10) == 0) {
            const members = try fleet.getMembers(gpa.allocator());
            defer members.deinit();
            log.info("main: members={d}", .{members.items.len});
            for (members.items) |v| gpa.allocator().free(v);
        }
    }
}

// The allocator here is the allocator passed to Fleet's init function. `addr`'s
// format is "ip:port", e.g. "127.0.0.1:8080", and needs to be freed after use.
fn onJoinAddr(allocator: std.mem.Allocator, data: ?*UserData, addr: []const u8) !void {
    defer allocator.free(addr);
    if (data.?.skip_callback) return;
    try setJoinAddress(allocator, data.?.prefix, data.?.group, addr);
}

// We are using curl here as std.http.Client seems to not play well with this endpoint.
// The "seegmed7" in the url is our API key.
fn setJoinAddress(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    group: []const u8,
    addr: []const u8,
) !void {
    const enc = std.base64.Base64Encoder.init(std.base64.url_safe_alphabet_chars, '=');
    const buf = try allocator.alloc(u8, enc.calcSize(addr.len));
    defer allocator.free(buf);
    const out = enc.encode(buf, addr);
    const url = try std.fmt.allocPrint(
        allocator,
        "https://keyvalue.immanuel.co/api/KeyVal/UpdateValue/seegmed7/{s}-{s}/{s}",
        .{ prefix, group, out },
    );

    defer allocator.free(url);

    log.info("callback: setJoinAddress: url={s}", .{url});

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

// We are using curl here as std.http.Client seems to not play well with this endpoint.
// The "seegmed7" in the url is our API key. We are passing an arena allocator here.
fn getJoinAddress(allocator: std.mem.Allocator, prefix: []const u8, group: []const u8) ![]u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "https://keyvalue.immanuel.co/api/KeyVal/GetValue/seegmed7/{s}-{s}",
        .{ prefix, group },
    );

    log.info("callback: getJoinAddress: url={s}", .{url});

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "curl", url },
    });

    const out = std.mem.trim(u8, result.stdout, "\"");
    const dec = std.base64.Base64Decoder.init(std.base64.url_safe_alphabet_chars, '=');
    const buf = try allocator.alloc(u8, try dec.calcSizeForSlice(out));
    try dec.decode(buf, out);
    return buf;
}
