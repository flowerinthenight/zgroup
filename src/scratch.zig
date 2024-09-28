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

// test "httpget" {
//     var parent = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer parent.deinit();
//     const arena = parent.allocator();

//     var client = std.http.Client{ .allocator = arena };
//     defer client.deinit();

//     const endpoint = "https://keyvalue.immanuel.co/api/KeyVal/GetValue/seegmed7/chew";
//     const uri = try std.Uri.parse(endpoint);

//     const server_header_buffer: []u8 = try arena.alloc(u8, 8 * 1024 * 4);
//     var req = try client.open(.GET, uri, std.http.Client.RequestOptions{
//         .server_header_buffer = server_header_buffer,
//     });

//     defer req.deinit();

//     try req.send();
//     try req.finish();
//     try req.wait();

//     const repstr = try req.reader().readAllAlloc(arena, std.math.maxInt(usize));

//     dbg("reply={s}\n", .{repstr});
// }

// test "httppost" {
//     var parent = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer parent.deinit();
//     const arena = parent.allocator();

//     var client = std.http.Client{ .allocator = arena };
//     defer client.deinit();

//     const endpoint = "https://keyvalue.immanuel.co/api/KeyVal/UpdateValue/seegmed7/chew/something";
//     const uri = try std.Uri.parse(endpoint);

//     const server_header_buffer: []u8 = try arena.alloc(u8, 8 * 1024 * 4);
//     var req = try client.open(.POST, uri, std.http.Client.RequestOptions{
//         .server_header_buffer = server_header_buffer,
//         .extra_headers = &[_]std.http.Header{.{ .name = "content-length", .value = "9" }},
//     });

//     defer req.deinit();

//     try req.send();
//     try req.finish();
//     try req.wait();

//     const repstr = try req.reader().readAllAlloc(arena, std.math.maxInt(usize));

//     dbg("reply={s}\n", .{repstr});
// }

// test "httpfetch" {
//     var parent = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer parent.deinit();
//     const arena = parent.allocator();

//     var client = std.http.Client{ .allocator = arena };
//     defer client.deinit();

//     // https://api.keyval.org/get/chew
//     // const endpoint = "https://keyvalue.immanuel.co/api/KeyVal/UpdateValue/seegmed7/chew/something";
//     const endpoint = "https://api.keyval.org/set/chew/bloodboil";
//     const uri = try std.Uri.parse(endpoint);

//     var response_body = std.ArrayList(u8).init(arena);

//     const response = try client.fetch(std.http.Client.FetchOptions{
//         .method = std.http.Method.POST,
//         .location = .{ .uri = uri },
//         // .extra_headers = &[_]std.http.Header{.{ .name = "Content-Length", .value = "9" }},
//         .response_storage = .{ .dynamic = &response_body },
//     });

//     if (response.status != .ok) dbg("booooooo\n", .{});

//     const parsed_body = try response_body.toOwnedSlice();
//     dbg("RESPONSE: {s}\n", .{parsed_body});
// }

test "returnblock" {
    {
        dbg("block entry\n", .{});
        defer dbg("block exit\n", .{});
        if (true) return;
    }

    dbg("should not be here\n", .{});
}

test "accesslen" {
    const i: usize = 1;
    const buf = try std.fmt.allocPrint(std.testing.allocator, "hello world {d}", .{i});
    dbg("len={d}\n", .{buf.len});
    std.testing.allocator.free(buf);
    dbg("len={d}\n", .{buf.len});
}

test "comp" {
    var empty = try std.fmt.allocPrint(std.testing.allocator, "", .{});
    dbg("len_empty={d}\n", .{empty.len});
    const str = try std.fmt.allocPrint(std.testing.allocator, "hello", .{});
    defer std.testing.allocator.free(str);
    empty = str;
    dbg("len_empty={d}\n", .{empty.len});
}

test "envmap" {
    const allocator = std.testing.allocator;
    var envmap = try std.process.getEnvMap(allocator);
    defer envmap.deinit();

    var iter = envmap.iterator();
    while (iter.next()) |v| {
        dbg("{s}={s}\n", .{ v.key_ptr.*, v.value_ptr.* });
    }

    const path = envmap.getPtr("PATH");
    if (path) |v| {
        dbg("PATH={s}\n", .{v.*});
    } else {
        dbg("no PATH\n", .{});
    }
}
