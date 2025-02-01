const std = @import("std");
const uuid = @import("uuid.zig");

pub fn main() !void {
    var print: bool = false;
    var number: u32 = 1000;
    var enable_v4: bool = true;
    var enable_v7: bool = true;
    const builtin = @import("builtin");
    var args =
        if (builtin.os.tag == .windows or builtin.os.tag == .wasi)
        return
    else
        std.process.args();
    _ = args.next(); // trhow away the program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--print")) {
            print = true;
        } else if (std.mem.eql(u8, arg, "--disable-v4")) {
            enable_v4 = false;
        } else if (std.mem.eql(u8, arg, "--disable-v7")) {
            enable_v7 = false;
        } else {
            number = std.fmt.parseInt(u32, arg, 10) catch |err| switch (err) {
                error.InvalidCharacter, error.Overflow => {
                    const stderr = std.io.getStdErr().writer();
                    try std.fmt.format(stderr, "Usage: [<number of UUIDs, default 1000>] [--print] [--disable-v4] [--disable-v7]\n", .{});
                    std.process.exit(1);
                },
            };
        }
    }
    if (enable_v4) try benchmrk(4, number, print);
    if (enable_v7) try benchmrk(7, number, print);
}

fn benchmrk(version: u8, number: u32, print: bool) !void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.fmt.format(stderr, "WARNING: memory leak!\n", .{}) catch unreachable;
    const allocator = gpa.allocator();

    var print_buffer = try allocator.alloc(uuid.UUID, if (print) number else 0);
    defer allocator.free(print_buffer);
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < number) : (i += 1) {
        const my_uuid: uuid.UUID = switch (version) {
            4 => uuid.uuid4(),
            7 => uuid.uuid7(),
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

test "args - get an iterator, no allocation but not fully portable" {
    const builtin = @import("builtin");
    var args =
        if (builtin.os.tag == .windows or builtin.os.tag == .wasi)
        // this sample does not work on Windows and WASI
        return
    else
        // Linux, MacOS etc. can use the simpler args() method:
        std.process.args();

    while (args.next()) |arg| {
        _ = arg; // use arg
    }
}
