//! Universally Unique IDentifiers (UUIDs) RFC 9562
const std = @import("std");
const fmt = std.fmt;
const random = std.crypto.random;
const testing = std.testing;

pub const UuidError = error{ InvalidFormat, InvalidCharacter };
pub const Uuid = [36]u8;

pub const UUID = struct {
    /// Acts like a buffer for the stored bytes.
    bytes: [16]u8,

    /// Returns the UUID as a string.
    pub fn toString(self: UUID) Uuid {
        const chars = "0123456789abcdef";
        var buf: Uuid = undefined;
        var buf_ptr: usize = 0;
        for (self.bytes, 0..) |byte, i| {
            if (i == 4 or i == 6 or i == 8 or i == 10) {
                buf[buf_ptr] = '-';
                buf_ptr += 1;
            }
            buf[buf_ptr] = chars[byte >> 4];
            buf[buf_ptr + 1] = chars[byte & 15];
            buf_ptr += 2;
        }
        return buf;
    }

    /// Converts the UUID to its string representation.
    pub fn format(self: UUID, comptime _: []const u8, _: fmt.FormatOptions, writer: anytype) (@TypeOf(writer).Error)!void {
        try fmt.format(writer, "{}-{}-{}-{}-{}", .{
            fmt.fmtSliceHexLower(self.bytes[0..4]),
            fmt.fmtSliceHexLower(self.bytes[4..6]),
            fmt.fmtSliceHexLower(self.bytes[6..8]),
            fmt.fmtSliceHexLower(self.bytes[8..10]),
            fmt.fmtSliceHexLower(self.bytes[10..16]),
        });
    }
};

/// The Nil UUID is special form of UUID that is specified to have all 128 bits set to zero.
pub const nil: UUID = UUID{
    .bytes = .{0} ** 16,
};

/// The Max UUID is a special form of UUID that is specified to have all 128 bits set to 1.
pub const max: UUID = UUID{
    .bytes = .{0xFF} ** 16,
};

/// UUID Version 4
/// UUIDv4 is meant for generating UUIDs from truly random or pseudorandom numbers.
pub fn uuid4() UUID {
    var uuid: UUID = UUID{ .bytes = undefined };
    random.bytes(uuid.bytes[0..]);
    uuid.bytes[6] = (uuid.bytes[6] & 0x0F) | 0x40; // version
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80; // variant
    return uuid;
}

fn v7Timestamp() u60 {
    const Clock = struct {
        var mutex: std.Thread.Mutex = .{};
        var timestamp: u60 = 0;
    };
    Clock.mutex.lock();
    defer Clock.mutex.unlock();
    const nanos = std.time.nanoTimestamp();
    var timestamp: u60 = @intCast((@divTrunc(nanos, 1_000_000) << 12) | @divTrunc((@mod(nanos, 1_000_000) << 12), 1_000_000));
    if (timestamp <= Clock.timestamp) timestamp = Clock.timestamp + 1;
    Clock.timestamp = timestamp;
    return timestamp;
}

/// UUID Version 7
/// UUIDv7 features a time-ordered value field derived from the widely
/// implemented and well-known Unix Epoch timestamp source, the number of
/// milliseconds since midnight 1 Jan 1970 UTC, leap seconds excluded.
/// Generally, UUIDv7 has improved entropy characteristics over UUIDv1.
/// Monotonicity: Replace Leftmost Random Bits with Increased Clock Precision.
/// (Method 3)
pub fn uuid7() UUID {
    var uuid: UUID = UUID{ .bytes = undefined };
    random.bytes(uuid.bytes[8..]);

    const timestamp: u60 = v7Timestamp();
    uuid.bytes[0] = @intCast(timestamp >> 52 & 0xFF);
    uuid.bytes[1] = @intCast(timestamp >> 44 & 0xFF);
    uuid.bytes[2] = @intCast(timestamp >> 36 & 0xFF);
    uuid.bytes[3] = @intCast(timestamp >> 28 & 0xFF);
    uuid.bytes[4] = @intCast(timestamp >> 20 & 0xFF);
    uuid.bytes[5] = @intCast(timestamp >> 12 & 0xFF);
    uuid.bytes[6] = @intCast((timestamp >> 8 & 0x0F) | 0x70); // version
    uuid.bytes[7] = @intCast(timestamp & 0xFF);
    uuid.bytes[8] = @intCast((uuid.bytes[8] & 0x3F) | 0x80); // variant
    return uuid;
}

/// Creates a UUID from the UUID string format.
pub fn fromString(buf: []const u8) UuidError!UUID {
    if (buf.len != 36 or buf[8] != '-' or buf[13] != '-' or buf[18] != '-' or buf[23] != '-')
        return error.InvalidFormat;
    var uuid: UUID = undefined;
    var i: usize = 0;
    var hyp_counter: u3 = 0;
    for (uuid.bytes[0..]) |*byte| {
        if (buf[i] == '-') {
            i += 1;
            hyp_counter += 1;
            if (hyp_counter > 4) return error.InvalidFormat;
        }
        const hi = try fmt.charToDigit(buf[i], 16);
        const lo = try fmt.charToDigit(buf[i + 1], 16);
        byte.* = hi << 4 | lo;
        i += 2;
    }
    return uuid;
}

/// Creates a UUID from a u128-bit integer.
pub fn fromInt(int: u128) UUID {
    var uuid: UUID = undefined;
    std.mem.writeInt(u128, uuid.bytes[0..], int, .big);
    return uuid;
}

test "Nil UUID" {
    const nil_uuid_str = nil.toString();
    try testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", &nil_uuid_str);
}

test "Max UUID" {
    const max_uuid_str = max.toString();
    try testing.expectEqualStrings("ffffffff-ffff-ffff-ffff-ffffffffffff", &max_uuid_str);
}

test "version and variant" {
    const uuid_1: UUID = uuid4();
    try testing.expectEqual(4, uuid_1.bytes[6] >> 4); // version
    try testing.expectEqual(2, uuid_1.bytes[8] >> 6); // variant
    const uuid_2: UUID = uuid7();
    try testing.expectEqual(7, uuid_2.bytes[6] >> 4); // version
    try testing.expectEqual(2, uuid_2.bytes[8] >> 6); // variant
}

test "UUID v4 uniqueness" {
    const num_uuids = 100;
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = &arena_allocator.allocator();
    const uuids = try allocator.alloc(UUID, num_uuids);
    defer allocator.free(uuids);

    // Generate UUIDs
    for (uuids) |*uuid| {
        uuid.* = uuid4();
    }
    for (uuids, 1..) |uuid_1, i| {
        // Check for duplicates
        for (uuids[i..]) |uuid_2| {
            try testing.expect(!std.mem.eql(u8, &uuid_1.bytes, &uuid_2.bytes));
        }
    }
}

test "UUID v7 monotonicity" {
    const num_uuids = 1_000;
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = &arena_allocator.allocator();
    const uuids = try allocator.alloc(UUID, num_uuids);
    defer allocator.free(uuids);

    // Generate UUIDs
    for (uuids) |*uuid| {
        uuid.* = uuid7();
    }
    var i: usize = 0;
    while (i < uuids.len - 1) : (i += 1) {
        try testing.expect(std.mem.lessThan(u8, &uuids[i].bytes, &uuids[i + 1].bytes));
    }
}

test "fromString" {
    const uuid = try fromString("01234567-89ab-CDEF-0123-456789abcdef");
    const uuid_str = uuid.toString();
    try testing.expectEqualStrings("01234567-89ab-cdef-0123-456789abcdef", &uuid_str);
}

test "fromInt" {
    const uuid = fromInt(0);
    try testing.expectEqual([1]u8{0x0} ** 16, uuid.bytes);
    try testing.expectEqual(max, fromInt(340282366920938463463374607431768211455));
}

test "fromInt and fromString match" {
    const uuid = try fromString("01234567-89ab-cdef-0123-456789abcdef");
    try testing.expectEqual(fromInt(0x0123456789ABCDEF0123456789ABCDEF), uuid);
}

test "format" {
    const uuids = [_][]const u8{
        "919108f7-52d1-4320-9bac-f847db4148a8",
        "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    };
    for (uuids) |uuid| {
        try testing.expectFmt(uuid, "{}", .{try fromString(uuid)});
    }
}

test "Parsing invalid UUID strings - error.InvalidFormat" {
    const invalid_uuid_strs = [_][]const u8{
        "123e4567-e89b-12d3-a456-42661417400", // Too short
        "123e4567-e89b-12d3-a456-4266141740000", // Too long
        "123e4567e89b12d3a456426614174000", // Missing hyphens
        "-01-4567-89ab-cdef-0123-456789abcdef", // Extra hyphens
        "", // Empty string
    };
    for (invalid_uuid_strs) |uuid_str| {
        try testing.expectError(error.InvalidFormat, fromString(uuid_str));
    }
}

test "Parsing invalid UUID strings - error.InvalidCharacter" {
    const invalid_uuid_strs = [_][]const u8{
        "g23e4567-e89b-12d3-a456-426614174000", // Invalid hex character 'g'
        "123e4567-e89b-12d3-a456-42661417400z", // Invalid hex character 'z'
        "123e4567-e89b-12d3-a456-42661417400 ", // Trailing space
        "123e4567-e89b-12d3-a456-42661417400-", // Trailing hyphen
        "------------------------------------", // Only hyphens
    };
    for (invalid_uuid_strs) |uuid_str| {
        try testing.expectError(error.InvalidCharacter, fromString(uuid_str));
    }
}
