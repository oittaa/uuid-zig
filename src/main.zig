const std = @import("std");
const Uuid = @import("Uuid.zig");

pub fn main() !void {
    var print: bool = false;
    var number: u64 = 1_000_000;
    var enable_v1: bool = true;
    var enable_v4: bool = true;
    var enable_v6: bool = true;
    var enable_v7: bool = true;
    const builtin = @import("builtin");
    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        var args = std.process.args();
        var index: usize = 0;
        while (args.next()) |arg| : (index += 1) {
            if (index == 0) continue; // skip the program name
            if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--print")) {
                print = true;
            } else if (std.mem.eql(u8, arg, "--disable-v1")) {
                enable_v1 = false;
            } else if (std.mem.eql(u8, arg, "--disable-v4")) {
                enable_v4 = false;
            } else if (std.mem.eql(u8, arg, "--disable-v6")) {
                enable_v6 = false;
            } else if (std.mem.eql(u8, arg, "--disable-v7")) {
                enable_v7 = false;
            } else {
                number = std.fmt.parseInt(u64, arg, 10) catch |err| switch (err) {
                    error.InvalidCharacter, error.Overflow => {
                        const stderr = std.io.getStdErr().writer();
                        try std.fmt.format(stderr, "Usage: [<number of UUIDs, default 1_000_000>] [--print] [--disable-v<1|4|6|7>]\n", .{});
                        std.process.exit(1);
                    },
                };
            }
        }
    }
    if (enable_v1) try benchmrk(1, number, print);
    if (enable_v4) try benchmrk(4, number, print);
    if (enable_v6) try benchmrk(6, number, print);
    if (enable_v7) try benchmrk(7, number, print);
}

fn benchmrk(version: u8, number: u64, print: bool) !void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.fmt.format(stderr, "WARNING: memory leak!\n", .{}) catch unreachable;
    const allocator = gpa.allocator();

    var print_buffer = try allocator.alloc(Uuid, if (print) number else 0);
    defer allocator.free(print_buffer);
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < number) : (i += 1) {
        const my_uuid: Uuid = switch (version) {
            1 => Uuid.uuid1(),
            4 => Uuid.uuid4(),
            6 => Uuid.uuid6(),
            7 => Uuid.uuid7(),
            else => {
                try std.fmt.format(stderr, "ERROR: unsupported version\n", .{});
                std.process.exit(1);
            },
        };
        if (print) {
            print_buffer[i] = my_uuid;
        }
    }
    const duration = timer.read();

    if (print) {
        for (print_buffer) |cur_uuid| {
            try std.fmt.format(stdout, "{}\n", .{cur_uuid});
        }
    } else {
        const duration_per_uuid = @as(u64, @intFromFloat(@as(f64, @floatFromInt(duration)) / @as(f64, @floatFromInt(number))));
        try std.fmt.format(stdout, "{d} UUIDv{d}s in {} = {}/UUID\n", .{ number, version, std.fmt.fmtDuration(duration), std.fmt.fmtDuration(duration_per_uuid) });
    }
}

test "Can generate UUIDs" {
    const testing = std.testing;
    const uuid_v1 = Uuid.uuid1();
    try testing.expectEqual(1, uuid_v1.version());
    const uuid_v4 = Uuid.uuid4();
    try testing.expectEqual(4, uuid_v4.version());
    const uuid_v6 = Uuid.uuid6();
    try testing.expectEqual(6, uuid_v6.version());
    const uuid_v7 = Uuid.uuid7();
    try testing.expectEqual(7, uuid_v7.version());
}
