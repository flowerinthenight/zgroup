//! zgroup is a library that can manage cluster membership and member failure detection.
//! It is based on the SWIM Protocol, specifically, SWIM+Inf.+Sus. variant of the gossip
//! protocol. Linux-only for now.
//!
//!   Reference: https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf
//!
const std = @import("std");
const backoff = @import("zbackoff");

const log = std.log.scoped(.zgroup);

pub fn Fleet(UserData: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,

        // See Config comments for these fields.
        name: []const u8,
        ip: []const u8,
        port: u16,
        protocol_time: u64,
        suspected_time: u64,
        ping_req_k: u32,

        // Our per-member data. Key format is "ip:port", eg. "127.0.0.1:8080".
        members: std.StringHashMap(MemberData),
        members_mtx: std.Thread.Mutex = .{},

        // Long-term references to all keys used in `members` and other intermediate
        // copies. Safer for access amidst all the addition and removals of items.
        refkeys: std.StringHashMap(void),
        refkeys_mtx: std.Thread.Mutex = .{},

        // Intermediate member queue for round-robin pings and randomization.
        ping_queue: std.ArrayList([]const u8),

        // For requesting our indirect ping agent(s).
        ping_req_data: *RequestPing = undefined, // set in run()
        ping_req_0: std.Thread.ResetEvent = .{}, // request
        ping_req_1: std.Thread.ResetEvent = .{}, // response

        // Internal queue for suspicion subprotocol.
        isd_queue: std.ArrayList(KeyInfo),
        isd_mtx: std.Thread.Mutex = .{},

        // Leader's heartbeat timeout.
        leader_hb: std.time.Timer,

        callbacks: Callbacks,

        // Raft-inspired leader election.
        lmtx: std.Thread.Mutex = .{},
        allowed: bool = false,
        allowed_tm: std.time.Timer,
        term: u64 = 0,
        state: NodeState = .follower,
        votes: u32 = 0,
        voted_for: []const u8,
        leader: []const u8,
        election_tm: std.time.Timer,
        candidate_tm: std.time.Timer,
        tm_min: u64 = std.time.ns_per_ms * 2000,
        tm_max: u64 = std.time.ns_per_ms * 3000,

        const NodeState = enum(u8) {
            follower,
            candidate,
            leader,
        };

        // SWIM protocol generic commands.
        const Command = enum(u8) {
            noop,
            ack,
            nack,
            join,
            ping,
            ping_req,
            heartbeat,
            req4votes,
            join2leader,
        };

        // Infection-style dissemination (ISD) commands.
        const IsdCommand = enum(u8) {
            noop,
            infect,
            suspect,
            confirm_alive,
            confirm_faulty,
        };

        // Possible member states.
        const MemberState = enum(u8) {
            alive,
            suspected,
            faulty,
        };

        const KeyInfo = struct {
            key: []const u8,
            state: MemberState,
            incarnation: u64 = 0,
            isd_cmd: IsdCommand = .noop,
        };

        // Our generic UDP comms/protocol payload.
        const Message = packed struct {
            name: u64 = 0,
            // Section for ping, ping_req, ack, nack.
            cmd: Command = .noop,
            src_ip: u32 = 0,
            src_port: u16 = 0,
            src_state: MemberState = .alive,
            src_incarnation: u64 = 0,
            dst_cmd: IsdCommand = .noop,
            dst_ip: u32 = 0,
            dst_port: u16 = 0,
            dst_state: MemberState = .alive,
            dst_incarnation: u64 = 0,
            // Infection-style dissemination section.
            isd_cmd: IsdCommand = .noop,
            isd_ip: u32 = 0,
            isd_port: u16 = 0,
            isd_state: MemberState = .alive,
            isd_incarnation: u64 = 0,
            // For leader election protocol.
            // Format:
            //   |----- cmd -----|-- port (u16) --|----------- IP address (u32) ----------|
            //   0000000000000011.1111111111111111.0000000011111111111111111111111111111111
            leader_proto: u64 = 0,
        };

        // Per-member context data.
        const MemberData = struct {
            state: MemberState = .alive,
            age_suspected: std.time.Timer = undefined,
            age_faulty: std.time.Timer = undefined,
            incarnation: u64 = 0,
            targets: std.ArrayList([]const u8),
        };

        // Commands used for leader election protocol.
        const LeaderCmd = enum(u8) {
            noop,
            heartbeat,
            invalidate,
        };

        pub const Callbacks = struct {
            /// Optional context data; to be passed back to the callback function(s).
            data: ?*UserData,

            /// Optional callback for the leader. Note that the internal leader election
            /// is best-effort only, and is provided to the caller for the purpose of
            /// providing an option for setting up facilities for other nodes to join the
            /// group. The address format is "ip:port", e.g. "127.0.0.1:8080".
            ///
            /// For example, you might want to setup a discovery service (e.g. K/V store)
            /// where you will store the address from the callback during invocation.
            /// Other joining nodes can then use the store to query the join address.
            ///
            /// Best-effort here means that there might be a brief moment where there
            /// will be multiple leaders calling the callback from multiple nodes during
            /// leader transitions; under normal conditions, there should only be one
            /// leader calling the callback function.
            onLeader: ?*const fn (std.mem.Allocator, ?*UserData, []const u8) anyerror!void,

            /// If > 0, callback will be called every `protocol_time * val`. For example,
            /// if your protocol time is 2s and this value is 10, `onLeader` will be
            /// called every 20s. Default (0) means every `protocol_time`; same as 1.
            on_leader_every: u64 = 0,
        };

        /// Config for init().
        pub const Config = struct {
            /// We use the name as group identifier when groups are running over the
            /// same network. Max of 8 chars (u64 in payload).
            name: []const u8,

            /// Member IP address for UDP, eg. "0.0.0.0". Use init() to initialize.
            ip: []const u8,

            /// Member port number for UDP, eg. 8080.
            port: u16 = 8080,

            /// Our SWIM protocol timeout duration.
            protocol_time: u64 = std.time.ns_per_s * 2,

            /// Suspicion subprotocol timeout duration.
            suspected_time: u64 = std.time.ns_per_s * 2,

            /// Number of members we will request to do indirect pings for us (agents).
            /// The only valid value at the moment is `1`.
            ping_req_k: u32 = 1,

            /// See `onLeader` field in `Callbacks` for more information.
            callbacks: Callbacks,
        };

        /// Create an instance of Self based on `config`. The `allocator` will be stored
        /// internally as the main internal allocator. Arena is not recommended as it's
        /// going to be used in the internal UDP server and the main loop which are
        /// expected to be long-running. Some areas will utilize an arena allocator
        /// based on the input allocator when it's appropriate.
        pub fn init(allocator: std.mem.Allocator, config: *const Config) !Self {
            return Self{
                .allocator = allocator,
                .name = if (config.name.len > 8) config.name[0..8] else config.name,
                .ip = config.ip,
                .port = config.port,
                .protocol_time = config.protocol_time,
                .suspected_time = config.suspected_time,
                .ping_req_k = config.ping_req_k,
                .members = std.StringHashMap(MemberData).init(allocator),
                .refkeys = std.StringHashMap(void).init(allocator),
                .ping_queue = std.ArrayList([]const u8).init(allocator),
                .isd_queue = std.ArrayList(KeyInfo).init(allocator),
                .leader_hb = try std.time.Timer.start(),
                .callbacks = config.callbacks,
                .leader = try std.fmt.allocPrint(allocator, "", .{}),
                .voted_for = try std.fmt.allocPrint(allocator, "", .{}),
                .election_tm = try std.time.Timer.start(),
                .candidate_tm = try std.time.Timer.start(),
                .allowed_tm = try std.time.Timer.start(),
            };
        }

        /// Cleanup Self instance. At the moment, it is expected for this
        /// code to be long running until process is terminated.
        pub fn deinit(self: *Self) void {
            log.debug("deinit:", .{});

            // TODO: See how to gracefuly exit threads.

            self.members.deinit();
            var it = self.refkeys.iterator();
            while (it.next()) |v| self.allocator.free(v.key_ptr.*);
            self.allocator.destroy(self.ping_req_data);
            self.refkeys.deinit();
            self.ping_queue.deinit();
            self.isd_queue.deinit();
        }

        /// Start group membership tracking.
        pub fn run(self: *Self) !void {
            log.debug("Message: size={d}, align={d}", .{
                @sizeOf(Message),
                @alignOf(Message),
            });

            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            _ = try self.ensureKeyRef(me);
            try self.upsertMember(me, .alive, 0, true);
            self.election_tm.reset();
            _ = try self.ensureKeyRef("0"); // dummy

            const server = try std.Thread.spawn(.{}, Self.listen, .{self});
            server.detach();
            const ticker = try std.Thread.spawn(.{}, Self.tick, .{self});
            ticker.detach();
            const ldr = try std.Thread.spawn(.{}, Self.leaderTick, .{self});
            ldr.detach();

            self.ping_req_data = try self.allocator.create(RequestPing);
            self.ping_req_data.self = self;
            const rp = try std.Thread.spawn(.{}, Self.requestPing, .{self.ping_req_data});
            rp.detach();
        }

        /// Ask an instance to join an existing group. `joined` will be
        /// set to true if joining is successful. We are joining the
        /// group through `dst_*`.
        pub fn join(
            self: *Self,
            name: []const u8,
            dst_ip: []const u8,
            dst_port: u16,
            joined: *bool,
        ) !void {
            var aa = std.heap.ArenaAllocator.init(self.allocator);
            defer aa.deinit(); // destroy arena in one go
            const arena = aa.allocator();

            const buf = try arena.alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));

            try self.presetMessage(msg);

            msg.cmd = .join;
            try self.setMsgSrcToOwn(msg);

            try self.send(dst_ip, dst_port, buf, null);

            switch (msg.cmd) {
                .ack => {
                    const nn = std.mem.readVarInt(u64, self.name, .little);
                    if (nn == msg.name) {
                        const key = try std.fmt.allocPrint(arena, "{s}:{d}", .{
                            dst_ip,
                            dst_port,
                        });

                        try self.upsertMember(key, .alive, 0, true);
                        self.allowed_tm.reset();
                        joined.* = true;

                        log.info("joined via {s}:{any}, name={s}", .{
                            dst_ip,
                            dst_port,
                            name,
                        });
                    }
                },
                else => {},
            }
        }

        /// Returns a list of active members from the group/cluster. Caller owns the returning
        /// list, as well as each items in the array, which are duplicated from the internal
        /// list to prevent crashes during access due to potential changes in the main list.
        pub fn getMembers(self: *Self, allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
            var tmp = std.ArrayList([]const u8).init(allocator);
            defer tmp.deinit();

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var it = self.members.iterator();
                while (it.next()) |v| {
                    if (v.value_ptr.state == .faulty) continue;
                    try tmp.append(v.key_ptr.*);
                }
            }

            var out = std.ArrayList([]const u8).init(allocator);

            if (tmp.items.len == 0) return out;

            for (tmp.items) |v| {
                const kdup = try allocator.dupe(u8, v);
                try out.append(kdup);
            }

            return out;
        }

        /// Returns the current leader of the group/cluster. Caller owns the returned
        /// buffer. The returned buffer format is "ip:port", e.g. "127.0.0.1:8080".
        pub fn getLeader(self: *Self, allocator: std.mem.Allocator) !?[]const u8 {
            const n = self.getCounts();
            if ((n[0] + n[1]) < 2) return try std.fmt.allocPrint(allocator, "{s}:{d}", .{
                self.ip,
                self.port,
            });

            var bo = backoff.Backoff{};
            for (0..3) |_| {
                if (self.leader_hb.read() < self.protocol_time) break;
                std.time.sleep(bo.pause());
            } else return null;

            const al = try self.getAssumedLeader();
            const ipb = std.mem.asBytes(&al[0]);
            return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{
                ipb[0],
                ipb[1],
                ipb[2],
                ipb[3],
                al[1],
            });
        }

        // Run internal UDP server for comms.
        fn listen(self: *Self) !void {
            log.info("Starting UDP server on :{d}...", .{self.port});

            const name = std.mem.readVarInt(u64, self.name, .little);
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

            // One allocation for the duration of this function.
            const msg: *Message = @ptrCast(@alignCast(buf));

            const addr = try std.net.Address.resolveIp(self.ip, self.port);
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM,
                std.posix.IPPROTO.UDP,
            );

            defer std.posix.close(sock);
            try setWriteTimeout(sock, 5_000_000);
            try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
            var src_addr: std.posix.sockaddr = undefined;
            var src_addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

            var i: usize = 0;
            while (true) : (i += 1) {
                const len = std.posix.recvfrom(
                    sock,
                    buf,
                    0,
                    &src_addr,
                    &src_addrlen,
                ) catch |err| {
                    log.err("recvfrom failed: {any}", .{err});
                    std.time.sleep(std.time.ns_per_ms * 500);
                    continue;
                };

                var aa = std.heap.ArenaAllocator.init(self.allocator);
                defer aa.deinit(); // destroy arena in one go
                const arena = aa.allocator();

                switch (msg.isd_cmd) {
                    .infect,
                    .confirm_alive,
                    => try self.handleIsd(arena, msg, false),
                    .suspect => try self.handleSuspicion(arena, msg),
                    .confirm_faulty => try self.handleConfirmFaulty(arena, msg),
                    else => {},
                }

                // Main protocol message handler.
                switch (msg.cmd) {
                    .join => b: {
                        if (msg.name == name) {
                            const key = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            try self.upsertMember(key, .alive, msg.src_incarnation, true);

                            // Inform current leader (if any) of this new join.
                            msg.dst_ip = msg.src_ip;
                            msg.dst_port = msg.src_port;
                            try self.setMsgSrcToOwn(msg);

                            log.debug("{s} is joining, inform leader [{s}]", .{ key, self.leader });

                            self.informLeaderOfJoin(buf) catch |err|
                                log.debug("informLeaderOfJoin failed: {any}", .{err});

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            msg.cmd = .ack;
                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});

                            break :b;
                        }

                        msg.cmd = .nack;
                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .ping => {
                        //
                        // Payload information:
                        //
                        //   src_*: caller/requester
                        //   dst_*: ISD (piggyback)
                        //   isd_*: ISD
                        //
                        msg.cmd = .nack; // default

                        if (msg.name == name) {
                            msg.cmd = .ack;
                            const src = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            try self.upsertMember(src, .alive, msg.src_incarnation, true);

                            if (msg.dst_cmd == .infect) {
                                const dst = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);
                                try self.upsertMember(
                                    dst,
                                    msg.dst_state,
                                    msg.dst_incarnation,
                                    false,
                                );
                            }

                            if (msg.isd_cmd == .noop) {
                                const n = self.getCounts();
                                if ((n[0] + n[1]) < msg.isd_incarnation) {
                                    self.allowed_tm.reset();
                                    @atomicStore(
                                        bool,
                                        &self.allowed,
                                        false,
                                        std.builtin.AtomicOrder.seq_cst,
                                    );
                                } else @atomicStore(
                                    bool,
                                    &self.allowed,
                                    true,
                                    std.builtin.AtomicOrder.seq_cst,
                                );
                            }

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            // Use both dst_* and isd_* for ISD info.
                            var excludes: [1][]const u8 = .{src};
                            try self.setMsgDstAndIsd(arena, msg, &excludes);

                            // Handle leader protocol.
                            var ipm = msg.leader_proto & 0x00000000FFFFFFFF;
                            var portm = (msg.leader_proto & 0x0000FFFF00000000) >> 32;
                            const cmdm: LeaderCmd = @enumFromInt((msg.leader_proto &
                                0xF000000000000000) >> 60);

                            if (cmdm == .heartbeat) b: {
                                const al = try self.getAssumedLeader();
                                if ((al[0] + al[1]) <= (ipm + portm)) {
                                    _ = self.leader_hb.lap();
                                    break :b;
                                }

                                const hb: u64 = @intFromEnum(LeaderCmd.invalidate);
                                ipm = al[0] & 0x00000000FFFFFFFF;
                                portm = (al[1] << 32) & 0x0000FFFF00000000;
                                msg.leader_proto = (hb << 60) | ipm | portm;
                            }
                        }

                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .ping_req => b: {
                        //
                        // Payload information:
                        //
                        //   src_*: caller/requester (we are the agent)
                        //   dst_*: target of the ping-request
                        //   isd_*: ISD
                        //
                        if (msg.name == name) {
                            const src = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            try self.upsertMember(src, msg.src_state, msg.src_incarnation, true);

                            const dst = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);

                            log.debug("({d}) ping-req: requested to ping {s}", .{ len, dst });

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            // Use both dst_* and isd_* for ISD info.
                            var excludes: [1][]const u8 = .{dst};
                            try self.setMsgDstAndIsd(arena, msg, &excludes);

                            // Handle leader protocol (egress).
                            try self.setLeaderProtoSend(msg);

                            const ack = self.ping(dst) catch false;

                            msg.cmd = .nack; // default

                            if (ack) {
                                // The src_* info here is the original ping target.
                                // Copy its info to the dst_* section before overwriting.
                                msg.cmd = .ack;
                                msg.dst_ip = msg.src_ip;
                                msg.dst_port = msg.src_port;
                                msg.dst_state = msg.src_state;
                                msg.dst_incarnation = msg.src_incarnation;

                                try self.upsertMember(dst, .alive, msg.src_incarnation, true);

                                // Handle leader protocol (ingress).
                                self.setLeaderProtoRecv(msg);
                            }

                            // Always set src_* to own info.
                            try self.setMsgSrcToOwn(msg);

                            const isd = try self.getIsdInfo(arena, 1);
                            if (isd.items.len > 0) {
                                msg.isd_cmd = .infect;
                                try setMsgSection(msg, .isd, isd.items[0]);
                            }

                            // Handle leader protocol (egress).
                            try self.setLeaderProtoSend(msg);

                            _ = std.posix.sendto(
                                sock,
                                std.mem.asBytes(msg),
                                0,
                                &src_addr,
                                src_addrlen,
                            ) catch |err| log.err("sendto failed: {any}", .{err});

                            break :b;
                        }

                        // Not in this group.
                        self.presetMessage(msg) catch {};
                        msg.cmd = .nack;

                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .heartbeat => {
                        msg.cmd = .nack;
                        const term = self.getTerm();
                        if (msg.leader_proto >= term) {
                            msg.cmd = .ack;
                            const tc = self.getTermAndN(msg);

                            // log.debug("[{d}] received heartbeat, set term={d} ", .{ i, tc[0] });

                            self.setTerm(tc[0]);
                            self.setVotes(0);
                            self.election_tm.reset();
                            self.setState(.follower);

                            const src = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            const lkey = try self.ensureKeyRef(src);

                            // log.debug("[{d}] received heartbeat from {s}", .{ i, lkey });

                            {
                                self.lmtx.lock();
                                defer self.lmtx.unlock();
                                self.leader = lkey;
                                self.voted_for = self.refkeys.getKeyPtr("0").?.*;
                            }
                        }

                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .req4votes => {
                        msg.cmd = .nack;
                        var voted = false;

                        {
                            self.lmtx.lock();
                            defer self.lmtx.unlock();
                            if (self.voted_for.len > 1) voted = true;
                        }

                        const term = self.getTerm();

                        // log.debug("req4votes: my_term={d}, in_term={d}", .{ term, msg.leader_proto });
                        // log.debug("req4votes: voted_for={s}, voted={any}", .{ self.voted_for, voted });

                        if (msg.leader_proto >= term and !voted and self.getState() != .leader) {
                            msg.cmd = .ack;
                            self.setTerm(msg.leader_proto);

                            const src = try keyFromIpPort(arena, msg.src_ip, msg.src_port);
                            const vkey = try self.ensureKeyRef(src);

                            // log.debug("[{d}] received req4votes from {s}", .{ i, vkey });

                            {
                                self.lmtx.lock();
                                defer self.lmtx.unlock();
                                self.voted_for = vkey;
                                log.debug("req4votes: voted_for={s}", .{self.voted_for});
                            }
                        }

                        _ = std.posix.sendto(
                            sock,
                            std.mem.asBytes(msg),
                            0,
                            &src_addr,
                            src_addrlen,
                        ) catch |err| log.err("sendto failed: {any}", .{err});
                    },
                    .join2leader => b: {
                        const state = self.getState();
                        if (state != .leader) break :b;
                        const dst = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);
                        const pdst = try self.ensureKeyRef(dst);
                        log.debug("[{d}] received join2leader, add {s}", .{ i, pdst });
                        try self.upsertMember(pdst, .alive, 0, false);
                    },
                    else => {},
                }

                self.presetMessage(msg) catch {};
            }
        }

        // Thread running the SWIM protocol.
        fn tick(self: *Self) !void {
            var i: usize = 0;
            while (true) : (i += 1) {
                var aa = std.heap.ArenaAllocator.init(self.allocator);
                defer aa.deinit(); // destroy arena in one go
                const arena = aa.allocator();

                // log.debug("[{d}]", .{i}); // log separator

                var tm = try std.time.Timer.start();
                var me_key: ?[]const u8 = null;
                var me_inc: u64 = 0;

                {
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var it = self.members.iterator();
                    while (it.next()) |v| {
                        if (!self.keyIsMe(v.key_ptr.*)) continue;
                        if (v.value_ptr.state == .alive) break;
                        v.value_ptr.state = .alive;
                        me_key = v.key_ptr.*;
                        me_inc = v.value_ptr.incarnation + 1;
                        break;
                    }
                }

                if (me_key) |mk| {
                    self.isd_mtx.lock();
                    defer self.isd_mtx.unlock();
                    try self.isd_queue.append(.{
                        .key = mk,
                        .state = .alive,
                        .isd_cmd = .confirm_alive,
                        .incarnation = me_inc,
                    });
                }

                // const counts = self.getCounts();
                // log.debug("[{d}] members: alive={d}, suspected={d}, faulty={d}, total={d}", .{
                //     i,
                //     counts[0],
                //     counts[1],
                //     counts[2],
                //     counts[3],
                // });

                var key_ptr: ?[]const u8 = null;
                const pt = try self.getPingTarget(arena);
                if (pt) |v| key_ptr = v; // ensure non-null

                if (key_ptr) |ping_key| {
                    // log.debug("[{d}] try pinging {s}", .{ i, ping_key });

                    switch (self.ping(ping_key) catch false) {
                        false => {
                            // Let's do indirect ping for this suspicious node.
                            // var prtm = try std.time.Timer.start();
                            // defer log.debug("[{d}] ping-req took {any}", .{
                            //     i,
                            //     std.fmt.fmtDuration(prtm.read()),
                            // });

                            // var do_suspected = false;
                            // var excludes: [1][]const u8 = .{ping_key};
                            // const agents = try self.getRandomMember(
                            //     arena,
                            //     &excludes,
                            //     self.ping_req_k,
                            // );

                            // if (agents.items.len == 0) do_suspected = true else {
                            //     log.debug("[{d}] ping-req: agent(s)={d}", .{ i, agents.items.len });

                            //     self.ping_req_data.src = agents.items[0];
                            //     self.ping_req_data.dst = ping_key;

                            //     self.ping_req_0.set();
                            //     self.ping_req_1.wait();
                            //     if (!self.ping_req_data.ack) do_suspected = true;
                            //     self.ping_req_1.reset();
                            // }

                            // if (do_suspected) b: {
                            //     const ki = self.getKeyInfo(ping_key);
                            //     if (ki) |_| {} else break :b;
                            //     try self.setMemberInfo(
                            //         ping_key,
                            //         .suspected,
                            //         ki.?.incarnation,
                            //         true,
                            //     );
                            // }

                            b: {
                                const ki = self.getKeyInfo(ping_key);
                                if (ki) |_| {} else break :b;
                                try self.setMemberInfo(
                                    ping_key,
                                    .suspected,
                                    ki.?.incarnation,
                                    true,
                                );
                            }
                        },
                        else => {
                            // log.debug("[{d}] ack from {s}", .{ i, ping_key });

                            // TEST: start
                            // if (i > 0 and i <= 100 and @mod(i, 20) == 0) {
                            //     log.debug("[{d}] --- trigger suspect for {s}", .{ i, ping_key });
                            //     self.isd_mtx.lock();
                            //     defer self.isd_mtx.unlock();
                            //     try self.isd_queue.append(.{
                            //         .key = ping_key,
                            //         .state = .suspected,
                            //         .incarnation = 0,
                            //         .isd_cmd = .suspect,
                            //     });
                            // }
                            // TEST: end
                        },
                    }
                }

                // Setup leader callback. Mainly for joining.
                var mod = self.callbacks.on_leader_every;
                if (mod == 0) mod = 1;
                if (i > 0 and @mod(i, mod) == 0) b: {
                    const al = self.getAssumedLeader() catch break :b;
                    if (!al[2]) break :b;
                    if (self.callbacks.onLeader) |_| {} else break :b;
                    const me = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{
                        self.ip,
                        self.port,
                    });

                    try self.callbacks.onLeader.?(
                        self.allocator,
                        self.callbacks.data,
                        me,
                    );
                }

                try self.removeFaultyMembers();

                // Suspected to faulty.
                var s2f = std.ArrayList([]const u8).init(arena);

                {
                    self.members_mtx.lock();
                    defer self.members_mtx.unlock();
                    var it = self.members.iterator();
                    while (it.next()) |v| {
                        if (self.keyIsMe(v.key_ptr.*)) continue;
                        if (v.value_ptr.state != .suspected) continue;
                        if (v.value_ptr.age_suspected.read() < self.suspected_time) continue;
                        try s2f.append(v.key_ptr.*);
                    }
                }

                for (s2f.items) |v| try self.setMemberInfo(v, .faulty, null, false);

                // Pause before the next tick.
                const elapsed = tm.read();
                if (elapsed < self.protocol_time) {
                    const left = self.protocol_time - elapsed;
                    // log.debug("[{d}] sleep for {any}", .{ i, std.fmt.fmtDuration(left) });
                    std.time.sleep(left);
                }
            }
        }

        fn leaderTick(self: *Self) !void {
            const buf = try self.allocator.alloc(u8, @sizeOf(Message));
            defer self.allocator.free(buf); // release buffer

            // One allocation for the duration of this function.
            const msg: *Message = @ptrCast(@alignCast(buf));

            const seed = std.crypto.random.int(u64);
            var prng = std.rand.DefaultPrng.init(seed);
            const random = prng.random();
            var i: usize = 0;
            while (true) : (i += 1) {
                const skip = true;
                const n = self.getCounts();
                if ((n[0] + n[1]) < 3 or skip) {
                    std.time.sleep(random.intRangeAtMost(
                        u64,
                        self.tm_min,
                        self.tm_max,
                    ));

                    continue;
                }

                const allowed = @atomicLoad(
                    bool,
                    &self.allowed,
                    std.builtin.AtomicOrder.seq_cst,
                );

                var aa = std.heap.ArenaAllocator.init(self.allocator);
                defer aa.deinit(); // destroy arena in one go
                const arena = aa.allocator();

                // log.debug("[{d}]", .{i}); // log separator

                self.presetMessage(msg) catch {};

                switch (self.getState()) {
                    .follower => {
                        if (self.allowed_tm.read() >= self.protocol_time * (n[0] + n[1])) {
                            @atomicStore(
                                bool,
                                &self.allowed,
                                true,
                                std.builtin.AtomicOrder.seq_cst,
                            );
                        }

                        const rand = random.intRangeAtMost(
                            u64,
                            self.tm_min,
                            self.tm_max,
                        );

                        if (!allowed) {
                            std.time.sleep(rand);
                            continue;
                        }

                        if (self.election_tm.read() <= self.tm_min) {
                            std.time.sleep(rand);
                            continue;
                        }

                        _ = self.incTermAndGet();
                        _ = self.voteForSelf();
                        self.setState(.candidate);
                        self.candidate_tm.reset();
                    },
                    .candidate => {
                        var bl = std.ArrayList([]const u8).init(arena);
                        defer bl.deinit();

                        {
                            self.members_mtx.lock();
                            defer self.members_mtx.unlock();
                            var iter = self.members.iterator();
                            while (iter.next()) |v| {
                                if (v.value_ptr.state != .alive) continue;
                                if (self.keyIsMe(v.key_ptr.*)) continue;
                                try bl.append(v.key_ptr.*);
                            }
                        }

                        if (bl.items.len == 0) {
                            std.time.sleep(random.intRangeAtMost(
                                u64,
                                self.tm_min,
                                self.tm_max,
                            ));

                            continue;
                        }

                        log.debug("[{d}:{d}] req4votes to {d} nodes", .{
                            i,
                            self.getTerm(),
                            bl.items.len,
                        });

                        var to_leader = false;
                        for (bl.items) |k| {
                            if (self.getState() == .follower) break;

                            msg.cmd = .req4votes;
                            try self.setMsgSrcToOwn(msg);
                            const sep = std.mem.indexOf(u8, k, ":") orelse continue;
                            const ip = k[0..sep];
                            const port = std.fmt.parseUnsigned(u16, k[sep + 1 ..], 10) catch
                                continue;

                            msg.leader_proto = self.getTerm();
                            self.send(ip, port, buf, null) catch continue;

                            if (msg.cmd != .ack) continue;

                            log.debug("[{d}:{d}] received vote from {s}", .{
                                i,
                                self.getTerm(),
                                k,
                            });

                            const majority = ((n[0] + n[1]) / 2) + 1;
                            const votes = self.incVotesAndGet();
                            if (votes >= majority) {
                                log.debug("[{d}:{d}] ********** attempt leader! got {d} votes, majority={d}, n={d}", .{
                                    i,
                                    self.getTerm(),
                                    votes,
                                    majority,
                                    n[0] + n[1],
                                });

                                self.setState(.leader);
                                to_leader = true;
                                break;
                            }
                        }

                        if (!to_leader) {
                            if (self.candidate_tm.read() > self.tm_min) {
                                log.debug("[{d}:{d}] lost the election, back to follower", .{
                                    i,
                                    self.getTerm(),
                                });

                                std.time.sleep(random.intRangeAtMost(
                                    u64,
                                    self.tm_min,
                                    self.tm_max,
                                ));

                                self.setState(.follower);
                                self.election_tm.reset();
                            } else std.time.sleep(random.intRangeAtMost(
                                u64,
                                self.tm_min,
                                self.tm_max,
                            ));
                        }
                    },
                    .leader => {
                        var tm = try std.time.Timer.start();
                        var deferlog = false;
                        defer {
                            if (deferlog) {
                                log.debug("[{d}:{d}] leader here, hb took {any}", .{
                                    i,
                                    self.getTerm(),
                                    std.fmt.fmtDuration(tm.read()),
                                });
                            }
                        }

                        var bl = std.ArrayList([]const u8).init(arena);
                        defer bl.deinit();

                        {
                            self.members_mtx.lock();
                            defer self.members_mtx.unlock();
                            var iter = self.members.iterator();
                            while (iter.next()) |v| {
                                if (v.value_ptr.state != .alive) continue;
                                if (self.keyIsMe(v.key_ptr.*)) continue;
                                try bl.append(v.key_ptr.*);
                            }
                        }

                        if (bl.items.len == 0) {
                            std.time.sleep(random.intRangeAtMost(
                                u64,
                                self.tm_min,
                                self.tm_max,
                            ));

                            continue;
                        }

                        log.debug("[{d}:{d}] leader here, hb to {d} nodes", .{
                            i,
                            self.getTerm(),
                            bl.items.len,
                        });

                        for (bl.items) |k| {
                            deferlog = true;
                            msg.cmd = .heartbeat;
                            try self.setMsgSrcToOwn(msg);
                            const sep = std.mem.indexOf(u8, k, ":") orelse continue;
                            const ip = k[0..sep];
                            const port = std.fmt.parseUnsigned(u16, k[sep + 1 ..], 10) catch
                                continue;

                            msg.leader_proto = self.getTerm();
                            self.setTermAndN(msg);
                            self.send(ip, port, buf, 50_000) catch |err| {
                                log.debug("[{d}:{d}] send (heartbeat) failed: {any}", .{
                                    i,
                                    self.getTerm(),
                                    err,
                                });

                                continue;
                            };
                        }

                        // TODO: This needs to be very short.
                        std.time.sleep(std.time.ns_per_ms * 500);
                    },
                }
            }
        }

        // Round-robin for one sweep, then randomize before doing another sweep.
        // We are passing in an arena allocator here.
        fn getPingTarget(self: *Self, allocator: std.mem.Allocator) !?[]const u8 {
            while (true) {
                const pop = self.ping_queue.popOrNull();
                if (pop) |v| return v;

                b: {
                    var tl = std.ArrayList([]const u8).init(allocator);

                    {
                        self.members_mtx.lock();
                        defer self.members_mtx.unlock();
                        var iter = self.members.iterator();
                        while (iter.next()) |v| {
                            if (v.value_ptr.state == .faulty) continue;
                            if (self.keyIsMe(v.key_ptr.*)) continue;
                            try tl.append(v.key_ptr.*);
                        }
                    }

                    switch (tl.items.len) {
                        0 => return null, // probably just us
                        1 => {
                            try self.ping_queue.append(tl.items[0]);
                            break :b;
                        },
                        else => {},
                    }

                    const seed = std.crypto.random.int(u64);
                    var prng = std.rand.DefaultPrng.init(seed);
                    const random = prng.random();
                    while (true) {
                        switch (tl.items.len) {
                            0 => break,
                            1 => {
                                try self.ping_queue.append(tl.items[0]);
                                break;
                            },
                            else => {},
                        }

                        const rv = random.uintAtMost(u64, tl.items.len - 1);
                        try self.ping_queue.append(tl.items[rv]);
                        _ = tl.swapRemove(rv);
                    }
                }
            }

            unreachable;
        }

        // Caller is responsible for releasing the returned memory.
        // We are passing in an arena allocator here.
        fn getRandomMember(
            self: *Self,
            allocator: std.mem.Allocator,
            excludes: [][]const u8,
            max: usize,
        ) !std.ArrayList([]const u8) {
            var hm = std.AutoHashMap(u64, []const u8).init(allocator);
            defer hm.deinit(); // noop

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var iter = self.members.iterator();
                while (iter.next()) |v| {
                    if (v.value_ptr.state == .faulty) continue;
                    if (self.keyIsMe(v.key_ptr.*)) continue;
                    var eql: usize = 0;
                    for (excludes) |x| {
                        if (std.mem.eql(u8, x, v.key_ptr.*)) eql += 1;
                    }

                    if (eql > 0) continue;
                    try hm.put(hm.count(), v.key_ptr.*);
                }
            }

            var out = std.ArrayList([]const u8).init(allocator);

            var limit = max;
            if (limit > hm.count()) limit = hm.count();
            if (hm.count() == 1 and limit > 0) {
                const get = hm.get(0);
                if (get) |v| try out.append(v);
                return out;
            }

            const seed = std.crypto.random.int(u64);
            var prng = std.rand.DefaultPrng.init(seed);
            const random = prng.random();
            for (0..limit) |_| {
                if (hm.count() == 0) break;
                while (true) {
                    if (hm.count() == 0) break;
                    const rv = random.uintAtMost(u64, hm.count() - 1);
                    const fr = hm.fetchRemove(rv);
                    if (fr) |v| try out.append(v.value);
                    break;
                }
            }

            return out;
        }

        // Caller is responsible for releasing the returned memory.
        // We are passing in an arena allocator here.
        fn getIsdInfo(
            self: *Self,
            allocator: std.mem.Allocator,
            max: usize,
        ) !std.ArrayList(KeyInfo) {
            var out = std.ArrayList(KeyInfo).init(allocator);
            self.isd_mtx.lock();
            defer self.isd_mtx.unlock();
            while (true) {
                const pop = self.isd_queue.popOrNull();
                if (pop) |v| try out.append(v) else break;
                if (out.items.len >= max) break;
            }

            return out;
        }

        // Setup both dst_* and isd_* sections of the payload.
        // We are passing in an arena allocator here.
        fn setMsgDstAndIsd(
            self: *Self,
            allocator: std.mem.Allocator,
            msg: *Message,
            excludes: [][]const u8,
        ) !void {
            b: {
                const dst = try self.getRandomMember(allocator, excludes, 1);
                if (dst.items.len == 0) break :b;
                msg.dst_cmd = .infect;
                const ki = self.getKeyInfo(dst.items[0]);
                if (ki) |_| {} else break :b;
                try setMsgSection(msg, .dst, ki.?);
            }

            // Setup main ISD info.
            const isd = try self.getIsdInfo(allocator, 1);
            if (isd.items.len > 0) {
                msg.isd_cmd = isd.items[0].isd_cmd;
                try setMsgSection(msg, .isd, isd.items[0]);
            }
        }

        // Setup both dst_* and isd_* sections of the payload.
        // We are passing in an arena allocator here.
        // fn _setMsgDstAndIsd(
        //     self: *Self,
        //     allocator: std.mem.Allocator,
        //     key: []const u8,
        //     msg: *Message,
        //     excludes: ?[][]const u8,
        // ) !void {
        //     b: {
        //         const dst = try self.getNextDstTarget(allocator, key, excludes);
        //         if (dst.items.len == 0) break :b;
        //         const ki = self.getKeyInfo(dst.items[0]);
        //         if (ki) |_| {} else break :b;
        //         msg.dst_cmd = .infect;
        //         try setMsgSection(msg, .dst, ki.?);
        //     }

        //     // Setup main ISD info.
        //     const isd = try self.getIsdInfo(allocator, 1);
        //     if (isd.items.len > 0) {
        //         msg.isd_cmd = isd.items[0].isd_cmd;
        //         try setMsgSection(msg, .isd, isd.items[0]);
        //     }
        // }

        // Caller is responsible for calling deinit on the returned list,
        // unless arena. We are passing in an arena allocator here.
        // fn getNextDstTarget(
        //     self: *Self,
        //     allocator: std.mem.Allocator,
        //     key: []const u8,
        //     excludes: ?[][]const u8,
        // ) !std.ArrayList([]const u8) {
        //     var out = std.ArrayList([]const u8).init(allocator);
        //     while (true) {
        //         self.members_mtx.lock();
        //         defer self.members_mtx.unlock();
        //         const val = self.members.getPtr(key);
        //         if (val) |_| {} else return out;

        //         const popn = val.?.targets.popOrNull();
        //         if (popn) |pop| {
        //             try out.append(pop);
        //             return out;
        //         }

        //         // If we're here, refill targets.
        //         var iter = self.members.iterator();
        //         while (iter.next()) |v| {
        //             if (v.value_ptr.state == .faulty) continue;
        //             if (std.mem.eql(u8, v.key_ptr.*, key)) continue;
        //             var eql: usize = 0;
        //             if (excludes) |excl| {
        //                 for (excl) |x| {
        //                     if (std.mem.eql(u8, x, v.key_ptr.*)) eql += 1;
        //                 }
        //             }

        //             if (eql > 0) continue;
        //             try val.?.targets.append(v.key_ptr.*);
        //         }
        //     }

        //     unreachable;
        // }

        // Ping a peer for liveness. Expected format for `key` is "ip:port",
        // eg. "127.0.0.1:8080". For pings, we use the src_* payload fields
        // to identify us, the sender.
        fn ping(self: *Self, key: []const u8) !bool {
            var aa = std.heap.ArenaAllocator.init(self.allocator);
            defer aa.deinit(); // destroy arena in one go
            const arena = aa.allocator();

            const sep = std.mem.indexOf(u8, key, ":") orelse return false;
            const ip = key[0..sep];
            const port = try std.fmt.parseUnsigned(u16, key[sep + 1 ..], 10);
            if (std.mem.eql(u8, ip, self.ip) and port == self.port) return true;

            const buf = try arena.alloc(u8, @sizeOf(Message));
            const msg: *Message = @ptrCast(@alignCast(buf));
            try self.presetMessage(msg);

            msg.cmd = .ping;
            try self.setMsgSrcToOwn(msg);

            // Use both dst_* and isd_* for ISD info.
            var excludes: [1][]const u8 = .{key};
            try self.setMsgDstAndIsd(arena, msg, &excludes);

            // Handle leader protocol (egress).
            try self.setLeaderProtoSend(msg);

            // Propagate number of members.
            if (msg.isd_cmd == .noop) {
                const n = self.getCounts();
                msg.isd_incarnation = n[0] + n[1];
            }

            try self.send(ip, port, buf, null);

            // Handle leader protocol (ingress).
            const cmdm: LeaderCmd = @enumFromInt((msg.leader_proto &
                0xF000000000000000) >> 60);

            if (cmdm != .invalidate) _ = self.leader_hb.lap();

            return switch (msg.cmd) {
                .ack => b: {
                    try self.upsertMember(key, .alive, msg.src_incarnation, true);

                    // Consume dst_* as piggybacked ISD info.
                    if (msg.dst_cmd == .infect) {
                        const k = try keyFromIpPort(arena, msg.dst_ip, msg.dst_port);
                        try self.upsertMember(k, msg.dst_state, msg.dst_incarnation, false);
                    }

                    // Consume isd_* as the main ISD info.
                    switch (msg.isd_cmd) {
                        .infect,
                        .confirm_alive,
                        => try self.handleIsd(arena, msg, false),
                        .suspect => try self.handleSuspicion(arena, msg),
                        .confirm_faulty => try self.handleConfirmFaulty(arena, msg),
                        else => {},
                    }

                    break :b true;
                },
                else => false,
            };
        }

        const RequestPing = struct {
            self: *Self,
            src: []const u8, // agent
            dst: []const u8, // target
            ack: bool = false,
        };

        // Our only agent for doing indirect pings for suspicious nodes. Long-running.
        fn requestPing(args: *RequestPing) !void {
            while (true) {
                args.self.ping_req_0.wait();
                defer {
                    args.self.ping_req_0.reset();
                    args.self.ping_req_1.set();
                }

                log.debug("[thread] try pinging {s} via {s}", .{ args.dst, args.src });

                var aa = std.heap.ArenaAllocator.init(args.self.allocator);
                defer aa.deinit(); // destroy arena in one go
                const arena = aa.allocator();

                const sep = std.mem.indexOf(u8, args.src, ":") orelse return;
                const ip = args.src[0..sep];
                const port = try std.fmt.parseUnsigned(u16, args.src[sep + 1 ..], 10);

                const buf = try arena.alloc(u8, @sizeOf(Message));
                const msg: *Message = @ptrCast(@alignCast(buf));
                try args.self.presetMessage(msg);
                msg.cmd = .ping_req;

                // Set src_* to our info, the sender.
                try args.self.setMsgSrcToOwn(msg);

                // The dst_* section is the target of our ping.
                try setMsgSection(msg, .dst, .{
                    .key = args.dst,
                    .state = .suspected, // will not be used
                    .incarnation = 0, // will not be used
                });

                // Handle ISD info.
                const isd = try args.self.getIsdInfo(arena, 1);
                if (isd.items.len > 0) {
                    msg.isd_cmd = .infect;
                    try setMsgSection(msg, .isd, isd.items[0]);
                }

                // Handle leader protocol (egress).
                try args.self.setLeaderProtoSend(msg);

                args.self.send(ip, port, buf, null) catch continue;

                // Handle leader protocol (ingress).
                args.self.setLeaderProtoRecv(msg);

                switch (msg.cmd) {
                    .ack => {
                        try args.self.upsertMember(
                            args.src,
                            msg.src_state,
                            msg.src_incarnation,
                            true,
                        );

                        try args.self.upsertMember(
                            args.dst,
                            msg.dst_state,
                            msg.dst_incarnation,
                            true,
                        );

                        // Consume isd_* as the main ISD info.
                        switch (msg.isd_cmd) {
                            .infect,
                            .confirm_alive,
                            => try args.self.handleIsd(arena, msg, false),
                            .suspect => try args.self.handleSuspicion(arena, msg),
                            .confirm_faulty => try args.self.handleConfirmFaulty(arena, msg),
                            else => {},
                        }

                        const ptr = &args.ack;
                        ptr.* = true;
                    },
                    .nack => try args.self.upsertMember(
                        args.src,
                        msg.src_state,
                        msg.src_incarnation,
                        false,
                    ),
                    else => {},
                }
            }
        }

        // Helper function for internal one-shot send/recv. The same message ptr is
        // used for both request and response payloads. If `tm_us` is not null,
        // default timeout will be 5s.
        fn send(_: *Self, ip: []const u8, port: u16, msg: []u8, tm_us: ?u32) !void {
            const addr = try std.net.Address.resolveIp(ip, port);
            const sock = try std.posix.socket(
                std.posix.AF.INET,
                std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
                0,
            );

            var tm: u32 = 1_000_000;
            if (tm_us) |v| tm = v;

            defer std.posix.close(sock);
            try setReadTimeout(sock, tm);
            try setWriteTimeout(sock, tm);
            try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
            _ = try std.posix.write(sock, msg);
            _ = try std.posix.recv(sock, msg, 0);
        }

        // Handle the isd_* infection protocol of the message payload.
        // We are passing in an arena allocator here.
        fn handleIsd(self: *Self, allocator: std.mem.Allocator, msg: *Message, force: bool) !void {
            const key = try keyFromIpPort(allocator, msg.isd_ip, msg.isd_port);
            try self.setMemberInfo(key, msg.isd_state, msg.isd_incarnation, force);
        }

        // Handle the isd_* suspicion protocol of the message payload.
        // We are passing in an arena allocator here.
        fn handleSuspicion(self: *Self, allocator: std.mem.Allocator, msg: *Message) !void {
            const key = try keyFromIpPort(allocator, msg.isd_ip, msg.isd_port);
            if (self.keyIsMe(key)) b: {
                try self.IncrementIncarnation();
                const pkey = self.getPersistentKeyFromKey(key);
                if (pkey) |_| {} else break :b;

                // self.isd_mtx.lock();
                // defer self.isd_mtx.unlock();
                // try self.isd_queue.append(.{
                //     .key = pkey.?,
                //     .state = .alive,
                //     .isd_cmd = .confirm_alive,
                //     .incarnation = try self.getIncarnation(), // ok since atomic
                // });

                return;
            }

            var suspected = std.ArrayList(KeyInfo).init(allocator);

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                const ptr = self.members.getPtr(key);
                if (ptr) |_| {} else return;

                try suspected.append(.{
                    .key = key,
                    .state = .suspected,
                    .isd_cmd = .confirm_alive,
                    .incarnation = ptr.?.incarnation,
                });
            }

            if (suspected.items.len == 0) return;

            const pkey = self.getPersistentKeyFromKey(key);
            if (pkey) |_| {} else return;

            // {
            //     self.isd_mtx.lock();
            //     defer self.isd_mtx.unlock();
            //     try self.isd_queue.append(.{
            //         .key = pkey.?,
            //         .state = suspected.items[0].state,
            //         .isd_cmd = suspected.items[0].isd_cmd,
            //         .incarnation = suspected.items[0].incarnation,
            //     });
            // }
        }

        // Handle the isd_* faulty protocol of the message payload.
        // We are passing in an arena allocator here.
        fn handleConfirmFaulty(self: *Self, allocator: std.mem.Allocator, msg: *Message) !void {
            const key = try keyFromIpPort(allocator, msg.isd_ip, msg.isd_port);
            if (!self.keyIsMe(key)) {
                try self.setMemberInfo(key, .faulty, null, true);
                return;
            }

            const pkey = self.getPersistentKeyFromKey(key);
            if (pkey) |_| {} else return;

            // self.isd_mtx.lock();
            // defer self.isd_mtx.unlock();
            // try self.isd_queue.append(.{
            //     .key = pkey.?,
            //     .state = .alive,
            //     .isd_cmd = .confirm_alive,
            //     .incarnation = try self.getIncarnation(), // ok since atomic
            // });
        }

        // NOTE: Not using locks; only atomic.
        fn getIncarnation(self: *Self) !u64 {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            const ptr = self.members.getPtr(me);
            if (ptr) |v| return @atomicLoad(
                u64,
                &v.incarnation,
                std.builtin.AtomicOrder.seq_cst,
            );

            unreachable;
        }

        // NOTE: Not using locks; only atomic.
        fn IncrementIncarnation(self: *Self) !void {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            const ptr = self.members.getPtr(me);
            if (ptr) |_| {} else return;
            _ = @atomicRmw(
                u64,
                &ptr.?.incarnation,
                std.builtin.AtomicRmwOp.Add,
                1,
                std.builtin.AtomicOrder.seq_cst,
            );
        }

        // Caller must free the returned memory.
        fn getOwnKey(self: *Self) ![]const u8 {
            return try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.ip, self.port });
        }

        // Expected format for `key` is ip:port, eg. 0.0.0.0:8080.
        fn keyIsMe(self: *Self, key: []const u8) bool {
            const sep = std.mem.indexOf(u8, key, ":") orelse return false;
            const ip = key[0..sep];
            const port = std.fmt.parseUnsigned(u16, key[sep + 1 ..], 10) catch return false;
            return if (std.mem.eql(u8, ip, self.ip) and port == self.port) true else false;
        }

        // Use the key from `members` when adding items (key) to the isd_queue.
        fn getPersistentKeyFromKey(self: *Self, key: []const u8) ?[]const u8 {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getKeyPtr(key);
            if (ptr) |v| return v.*;
            return null;
        }

        // [0] = # of alive members
        // [1] = # of suspected members
        // [2] = # of faulty members
        // [3] = total number of members
        fn getCounts(self: *Self) std.meta.Tuple(&.{ usize, usize, usize, usize }) {
            var n: [3]usize = .{ 0, 0, 0 };
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            var it = self.members.iterator();
            while (it.next()) |v| {
                switch (v.value_ptr.state) {
                    .alive => n[0] += 1,
                    .suspected => n[1] += 1,
                    .faulty => n[2] += 1,
                }
            }

            return .{
                n[0],
                n[1],
                n[2],
                self.members.count(),
            };
        }

        fn getKeyInfo(self: *Self, key: []const u8) ?KeyInfo {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const ptr = self.members.getPtr(key);
            if (ptr) |_| {} else return null;
            return .{
                .key = key,
                .state = ptr.?.state,
                .incarnation = ptr.?.incarnation,
            };
        }

        // We always assume the node with the largest ip(int)+port to be leader.
        // [0] - leader's (highest) ip in int format
        // [1] - leader's (highest) port number
        // [2] - true if we are the leader
        fn getAssumedLeader(self: *Self) !std.meta.Tuple(&.{ u32, u64, bool }) {
            var ipl: u32 = 0;
            var portl: u16 = 0;
            var me = false;
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            var it = self.members.iterator();
            while (it.next()) |v| {
                if (v.value_ptr.state == .faulty) continue;
                const sep = std.mem.indexOf(u8, v.key_ptr.*, ":") orelse continue;
                const ip = v.key_ptr.*[0..sep];
                const port = try std.fmt.parseUnsigned(u16, v.key_ptr.*[sep + 1 ..], 10);
                const addr = try std.net.Address.resolveIp(ip, port);
                if ((addr.in.sa.addr + port) > (ipl + portl)) {
                    ipl = addr.in.sa.addr;
                    portl = port;
                    me = std.mem.eql(u8, ip, self.ip) and port == self.port;
                }
            }

            return .{ ipl, portl, me };
        }

        fn setLeaderProtoSend(self: *Self, msg: *Message) !void {
            const n = self.getCounts();
            const lim = n[0] + n[1];
            if (lim < 2) return;
            const al = try self.getAssumedLeader();
            const hb: u64 = @intFromEnum(LeaderCmd.heartbeat);
            const ipl: u32 = al[0] & 0x00000000FFFFFFFF;
            const portl: u64 = (al[1] << 32) & 0x0000FFFF00000000;
            msg.leader_proto = (hb << 60) | ipl | portl;
        }

        fn setLeaderProtoRecv(self: *Self, msg: *Message) void {
            const cmdm: LeaderCmd = @enumFromInt((msg.leader_proto &
                0xF000000000000000) >> 60);
            if (cmdm != .invalidate) _ = self.leader_hb.lap();
        }

        fn setTermAndN(self: *Self, msg: *Message) void {
            const n = self.getCounts();
            const total = n[0] + n[1];
            const term = @atomicLoad(u64, &self.term, std.builtin.AtomicOrder.seq_cst);
            const mterm: u64 = term & 0x0000FFFFFFFFFFFF;
            const mcount: u64 = (total << 48) & 0xFFFF000000000000;
            msg.leader_proto = mcount | mterm;
        }

        // [0] - term
        // [1] - count
        fn getTermAndN(_: *Self, msg: *Message) std.meta.Tuple(&.{ u64, u64 }) {
            const term = msg.leader_proto & 0x0000FFFFFFFFFFFF;
            const count = (msg.leader_proto & 0xFFFF000000000000) >> 48;
            return .{ term, count };
        }

        // Set default values for the message.
        fn presetMessage(self: *Self, msg: *Message) !void {
            msg.name = std.mem.readVarInt(u64, self.name, .little);
            msg.cmd = .noop;
            msg.src_state = .alive;
            msg.dst_cmd = .noop;
            msg.dst_state = .alive;
            msg.isd_cmd = .noop;
            msg.isd_state = .alive;
            msg.leader_proto = 0;
        }

        fn setMsgSrcToOwn(self: *Self, msg: *Message) !void {
            const me = try self.getOwnKey();
            defer self.allocator.free(me);
            try setMsgSection(msg, .src, .{
                .key = me,
                .state = .alive,
                .incarnation = try self.getIncarnation(),
            });
        }

        // Add a new member or update an existing member's info. This function
        // duplicates the key using self.allocator when adding a new member,
        // not when updating an existing one.
        fn upsertMember(
            self: *Self,
            key: []const u8,
            state: ?MemberState,
            incarnation: ?u64,
            force: bool,
        ) !void {
            const contains = b: {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                break :b self.members.contains(key);
            };

            if (contains) {
                try self.setMemberInfo(key, state, incarnation, force);
                return;
            }

            const nkey = try self.allocator.dupe(u8, key);

            // Our copy of all member keys being allocated; to free later.
            if (!self.refkeys.contains(nkey)) try self.refkeys.put(nkey, {});

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                try self.members.put(nkey, .{
                    .age_suspected = try std.time.Timer.start(),
                    .age_faulty = try std.time.Timer.start(),
                    .targets = std.ArrayList([]const u8).init(self.allocator),
                });
            }

            try self.setMemberInfo(key, state, incarnation, true);
        }

        // `key` should be in fmt: "ip:port", e.g. "127.0.0.1:8080". We
        // duplicate `key` to our internal list to be able to free later.
        fn ensureKeyRef(self: *Self, key: []const u8) ![]const u8 {
            self.refkeys_mtx.lock();
            defer self.refkeys_mtx.unlock();
            if (self.refkeys.contains(key)) return self.refkeys.getKey(key).?;
            const dup = try self.allocator.dupe(u8, key);
            try self.refkeys.put(dup, {});
            return dup;
        }

        // Reference: SWIM:4.2
        // Order of preference:
        //
        //   {Alive:M, inc=i} overrides
        //    - {Suspect:M, inc=j}, i>j
        //    - {Alive:M, inc=j}, i>j
        //
        //   {Suspect:M, inc=i} overrides
        //    - {Suspect:M, inc=j}, i>j
        //    - {Alive:M, inc=j}, i>=j
        //
        //   {Faulty:M, inc=i} overrides
        //    - {Alive:M, inc=j}, any j
        //    - {Suspect:M, inc=j}, any j
        //
        fn setMemberInfo(
            self: *Self,
            key: []const u8,
            state: ?MemberState,
            incarnation: ?u64,
            force: bool,
        ) !void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const p = self.members.getPtr(key);
            if (p) |_| {} else return;

            var apply = false;
            var in_state: MemberState = .alive;
            var in_inc: u64 = p.?.incarnation;
            if (state) |s| in_state = s else return;
            if (incarnation) |inc| in_inc = inc;

            if (in_state == .alive) {
                if (p.?.state == .suspected and in_inc > p.?.incarnation) apply = true;
                if (p.?.state == .alive and in_inc > p.?.incarnation) apply = true;
            }

            if (in_state == .suspected) {
                if (p.?.state == .suspected and in_inc > p.?.incarnation) apply = true;
                if (p.?.state == .alive and in_inc >= p.?.incarnation) apply = true;
            }

            if (in_state == .faulty) apply = true;
            if (force) apply = true;

            if (!apply) return;

            if (p.?.state == .faulty and in_state == .alive) p.?.incarnation = 0;

            p.?.state = in_state;
            p.?.incarnation = in_inc;

            if (p.?.state == .suspected and in_state != .suspected) p.?.age_suspected.reset();
            if (p.?.state == .faulty and in_state != .faulty) p.?.age_faulty.reset();
        }

        // const SuspectToFaulty = struct {
        //     self: *Self,
        //     key: []const u8,
        // };

        // // To be run as a separate thread. Keep it suspected
        // // for a while before marking it as faulty.
        // fn suspectToFaulty(args: *SuspectToFaulty) !void {
        //     // Pause for a bit before we set to faulty.
        //     std.time.sleep(args.self.suspected_time);
        //     try args.self.setMemberInfo(args.key, .faulty, null, false);

        //     // Broadcast confirm_faulty to the group.
        //     args.self.isd_mtx.lock();
        //     defer args.self.isd_mtx.unlock();
        //     try args.self.isd_queue.append(.{
        //         .key = args.key,
        //         .state = .faulty,
        //         .isd_cmd = .confirm_faulty,
        //         .incarnation = try args.self.getIncarnation(), // ok since atomic
        //     });
        // }

        // Attempt removing faulty members after some time.
        fn removeFaultyMembers(self: *Self) !void {
            var rml = std.ArrayList([]const u8).init(self.allocator);
            defer rml.deinit();

            {
                self.members_mtx.lock();
                defer self.members_mtx.unlock();
                var it = self.members.iterator();
                const limit = self.protocol_time; // TODO: expose
                while (it.next()) |v| {
                    if (v.value_ptr.state != .faulty) continue;
                    if (v.value_ptr.age_faulty.read() > limit) {
                        try rml.append(v.key_ptr.*);
                    }
                }
            }

            for (rml.items) |v| self.removeMember(v);
        }

        // We don't free the key itself here; we will free through self.ref_keys.
        fn removeMember(self: *Self, key: []const u8) void {
            self.members_mtx.lock();
            defer self.members_mtx.unlock();
            const fr = self.members.fetchRemove(key);
            if (fr) |v| v.value.targets.deinit();
        }

        const MsgSection = enum {
            src,
            dst,
            isd,
        };

        // Set a section of the message payload with ip, port, and state info.
        fn setMsgSection(msg: *Message, section: MsgSection, info: KeyInfo) !void {
            const sep = std.mem.indexOf(u8, info.key, ":") orelse return;
            const ip = info.key[0..sep];
            const port = try std.fmt.parseUnsigned(u16, info.key[sep + 1 ..], 10);
            const addr = try std.net.Address.resolveIp(ip, port);

            switch (section) {
                .src => {
                    msg.src_ip = addr.in.sa.addr;
                    msg.src_port = port;
                    msg.src_state = info.state;
                    msg.src_incarnation = info.incarnation;
                },
                .dst => {
                    msg.dst_ip = addr.in.sa.addr;
                    msg.dst_port = port;
                    msg.dst_state = info.state;
                    msg.dst_incarnation = info.incarnation;
                },
                .isd => {
                    msg.isd_ip = addr.in.sa.addr;
                    msg.isd_port = port;
                    msg.isd_state = info.state;
                    msg.isd_incarnation = info.incarnation;
                },
            }
        }

        fn getState(self: *Self) NodeState {
            self.lmtx.lock();
            defer self.lmtx.unlock();
            return self.state;
        }

        fn setState(self: *Self, state: NodeState) void {
            self.lmtx.lock();
            defer self.lmtx.unlock();
            self.state = state;
        }

        // Best-effort basis only. `msg` should already contain the new join info
        // in the dst_* portion, as well as it's source info.
        fn informLeaderOfJoin(self: *Self, msg: []u8) !void {
            const leader = b: {
                self.lmtx.lock();
                defer self.lmtx.unlock();
                break :b self.leader;
            };

            if (leader.len < 2) return;

            const sep = std.mem.indexOf(u8, leader, ":") orelse return;
            const ip = leader[0..sep];
            const port = try std.fmt.parseUnsigned(u16, leader[sep + 1 ..], 10);

            try self.send(ip, port, msg, null);
        }

        fn getTerm(self: *Self) u64 {
            return @atomicLoad(
                u64,
                &self.term,
                std.builtin.AtomicOrder.seq_cst,
            );
        }

        fn setTerm(self: *Self, term: u64) void {
            @atomicStore(
                u64,
                &self.term,
                term,
                std.builtin.AtomicOrder.seq_cst,
            );
        }

        fn incTermAndGet(self: *Self) u64 {
            _ = @atomicRmw(
                u64,
                &self.term,
                std.builtin.AtomicRmwOp.Add,
                1,
                std.builtin.AtomicOrder.seq_cst,
            );

            return self.getTerm();
        }

        fn getVotes(self: *Self) u32 {
            return @atomicLoad(
                u32,
                &self.votes,
                std.builtin.AtomicOrder.seq_cst,
            );
        }

        fn setVotes(self: *Self, vote: u32) void {
            @atomicStore(
                u32,
                &self.votes,
                vote,
                std.builtin.AtomicOrder.seq_cst,
            );
        }

        fn voteForSelf(self: *Self) u32 {
            _ = @atomicRmw(
                u32,
                &self.votes,
                std.builtin.AtomicRmwOp.Add,
                1,
                std.builtin.AtomicOrder.seq_cst,
            );

            return self.getVotes();
        }

        fn incVotesAndGet(self: *Self) u32 {
            return self.voteForSelf();
        }
    };
}

/// Converts an ip and port to a string with format ip:port, eg. "127.0.0.1:8080".
/// Caller is responsible for releasing the returned memory.
fn keyFromIpPort(allocator: std.mem.Allocator, ip: u32, port: u16) ![]const u8 {
    const ipb = std.mem.asBytes(&ip);
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{
        ipb[0],
        ipb[1],
        ipb[2],
        ipb[3],
        port,
    });
}

/// Set socket read timeout in microseconds. Linux only.
pub fn setReadTimeout(socket: std.posix.socket_t, read: ?u32) !void {
    std.debug.assert(read == null or read.? != 0);
    const micros = read orelse 0;
    const opt = std.posix.timeval{
        .tv_sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
        .tv_usec = @intCast(@mod(micros, std.time.us_per_s)),
    };

    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.toBytes(opt)[0..],
    );
}

/// Set socket write timeout in microseconds. Linux only.
pub fn setWriteTimeout(socket: std.posix.socket_t, write: ?u32) !void {
    std.debug.assert(write == null or write.? != 0);
    const micros = write orelse 0;
    const opt = std.posix.timeval{
        .tv_sec = @intCast(@divTrunc(micros, std.time.us_per_s)),
        .tv_usec = @intCast(@mod(micros, std.time.us_per_s)),
    };

    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDTIMEO,
        std.mem.toBytes(opt)[0..],
    );
}
