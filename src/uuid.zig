//! Universally Unique IDentifiers (UUIDs) RFC 9562
const std = @import("std");
const fmt = std.fmt;
const hash = std.crypto.hash;
const random = std.crypto.random;
const testing = std.testing;

pub const UuidError = error{ InvalidFormat, InvalidCharacter };
pub const Uuid = [36]u8;

pub const UUID = struct {
    /// Acts like a buffer for the stored bytes.
    bytes: [16]u8,

    /// Returns the UUID as an u128 int.
    pub fn toInt(self: UUID) u128 {
        return std.mem.readInt(u128, self.bytes[0..], .big);
    }

    /// Returns the UUID as a string.
    pub fn toString(self: UUID) Uuid {
        const buf: *Uuid = fmt.bytesToHex(self.bytes[0..4], .lower) ++ "-" ++ fmt.bytesToHex(self.bytes[4..6], .lower) ++ "-" ++ fmt.bytesToHex(self.bytes[6..8], .lower) ++ "-" ++ fmt.bytesToHex(self.bytes[8..10], .lower) ++ "-" ++ fmt.bytesToHex(self.bytes[10..16], .lower);
        return buf.*;
    }

    /// Returns the UUID version number.
    pub fn version(self: UUID) u4 {
        return @truncate(self.bytes[6] >> 4);
    }

    /// Converts the UUID to its string representation.
    pub fn format(
        self: UUID,
        comptime f: []const u8,
        options: fmt.FormatOptions,
        writer: anytype,
    ) (@TypeOf(writer).Error)!void {
        _ = options;
        if (f.len != 0) fmt.invalidFmtError(f, self);
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

pub const namespace = struct {
    pub const dns = fromInt(0x6ba7b8109dad11d180b400c04fd430c8);
    pub const url = fromInt(0x6ba7b8119dad11d180b400c04fd430c8);
    pub const oid = fromInt(0x6ba7b8129dad11d180b400c04fd430c8);
    pub const x500 = fromInt(0x6ba7b8149dad11d180b400c04fd430c8);
};

/// UUID Version 1
/// UUIDv1 is a time-based UUID featuring a 60-bit timestamp represented by
/// Coordinated Universal Time (UTC) as a count of 100-nanosecond intervals
/// since 00:00:00.00, 15 October 1582 (the date of Gregorian reform to the
/// Christian calendar).
pub fn uuid1() UUID {
    var uuid: UUID = undefined;
    random.bytes(uuid.bytes[8..]);
    const timestamp: u60 = v6Timestamp();
    uuid.bytes[0] = @truncate(timestamp >> 24);
    uuid.bytes[1] = @truncate(timestamp >> 16);
    uuid.bytes[2] = @truncate(timestamp >> 8);
    uuid.bytes[3] = @truncate(timestamp);
    uuid.bytes[4] = @truncate(timestamp >> 40);
    uuid.bytes[5] = @truncate(timestamp >> 32);
    uuid.bytes[6] = @as(u8, @truncate(timestamp >> 56)) | 0x10; // version
    uuid.bytes[7] = @truncate(timestamp >> 48);
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80; // variant
    // After generating the 48-bit fully randomized node value, implementations
    // MUST set the least significant bit of the first octet of the Node ID to 1
    uuid.bytes[10] |= 1;
    return uuid;
}

/// UUID Version 3
/// UUIDv3 is meant for generating UUIDs from "names" that are drawn from, and unique within, some "namespace".
pub fn uuid3(ns: UUID, name: []const u8) UUID {
    var uuid: UUID = undefined;
    var md5 = hash.Md5.init(.{});
    md5.update(ns.bytes[0..]);
    md5.update(name);
    md5.final(uuid.bytes[0..]); // we can write directly since hash.Md5.digest_length is 16
    uuid.bytes[6] = (uuid.bytes[6] & 0x0F) | 0x30; // version
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80; // variant
    return uuid;
}

/// UUID Version 4
/// UUIDv4 is meant for generating UUIDs from truly random or pseudorandom numbers.
pub fn uuid4() UUID {
    var uuid: UUID = undefined;
    random.bytes(uuid.bytes[0..]);
    uuid.bytes[6] = (uuid.bytes[6] & 0x0F) | 0x40; // version
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80; // variant
    return uuid;
}

/// UUID Version 5
/// UUIDv5 is meant for generating UUIDs from "names" that are drawn from, and unique within, some "namespace".
pub fn uuid5(ns: UUID, name: []const u8) UUID {
    var uuid: UUID = undefined;
    var sha1 = hash.Sha1.init(.{});
    sha1.update(ns.bytes[0..]);
    sha1.update(name);
    var buf: [hash.Sha1.digest_length]u8 = undefined;
    sha1.final(buf[0..]);
    @memcpy(uuid.bytes[0..], buf[0..16]);
    uuid.bytes[6] = (uuid.bytes[6] & 0x0F) | 0x50; // version
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80; // variant
    return uuid;
}

fn v6Timestamp() u60 {
    // 0x01b21dd213814000 is the number of 100-ns intervals between the
    // UUID epoch 1582-10-15 00:00:00 and the Unix epoch 1970-01-01 00:00:00.
    const Clock = struct {
        var mutex: std.Thread.Mutex = .{};
        var timestamp: u60 = 0;
    };
    Clock.mutex.lock();
    defer Clock.mutex.unlock();
    const nanos = std.time.nanoTimestamp();
    var timestamp: u60 = @intCast(@divTrunc(nanos, 100) + 0x01b21dd213814000);
    if (timestamp <= Clock.timestamp) timestamp = Clock.timestamp + 1;
    Clock.timestamp = timestamp;
    return timestamp;
}

/// UUID Version 6
/// UUIDv6 is a field-compatible version of UUIDv1, reordered for improved DB locality.
pub fn uuid6() UUID {
    var uuid: UUID = undefined;
    random.bytes(uuid.bytes[8..]);
    const timestamp: u60 = v6Timestamp();
    std.mem.writeInt(u48, uuid.bytes[0..6], @truncate(timestamp >> 12), .big);
    uuid.bytes[6] = @as(u8, @truncate((timestamp >> 8) & 0x0F)) | 0x60; // version
    uuid.bytes[7] = @truncate(timestamp);
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
    var uuid: UUID = undefined;
    random.bytes(uuid.bytes[8..]);
    const timestamp: u60 = v7Timestamp();
    std.mem.writeInt(u48, uuid.bytes[0..6], @truncate(timestamp >> 12), .big);
    uuid.bytes[6] = @as(u8, @truncate((timestamp >> 8) & 0x0F)) | 0x70; // version
    uuid.bytes[7] = @truncate(timestamp);
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80; // variant
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
    const uuid_v1: UUID = uuid1();
    try testing.expectEqual(1, uuid_v1.bytes[6] >> 4); // version
    try testing.expectEqual(1, uuid_v1.version());
    try testing.expectEqual(2, uuid_v1.bytes[8] >> 6); // variant
    const uuid_v4: UUID = uuid4();
    try testing.expectEqual(4, uuid_v4.bytes[6] >> 4); // version
    try testing.expectEqual(4, uuid_v4.version());
    try testing.expectEqual(2, uuid_v4.bytes[8] >> 6); // variant
    const uuid_v6: UUID = uuid6();
    try testing.expectEqual(6, uuid_v6.bytes[6] >> 4); // version
    try testing.expectEqual(6, uuid_v6.version());
    try testing.expectEqual(2, uuid_v6.bytes[8] >> 6); // variant
    const uuid_v7: UUID = uuid7();
    try testing.expectEqual(7, uuid_v7.bytes[6] >> 4); // version
    try testing.expectEqual(7, uuid_v7.version());
    try testing.expectEqual(2, uuid_v7.bytes[8] >> 6); // variant
}

test "UUID v3" {
    try testing.expectEqual(16, hash.Md5.digest_length);
    const uuid = uuid3(namespace.dns, "www.example.com");
    const uuid_str = uuid.toString();
    try testing.expectEqualStrings("5df41881-3aed-3515-88a7-2f4a814cf09e", &uuid_str);
}

test "UUID v5" {
    try testing.expectEqual(20, hash.Sha1.digest_length);
    const uuid = uuid5(namespace.dns, "www.example.com");
    const uuid_str = uuid.toString();
    try testing.expectEqualStrings("2ed6657d-e927-568b-95e1-2665a8aea6a2", &uuid_str);
}

test "UUID v1 uniqueness" {
    const num_uuids = 100;
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = &arena_allocator.allocator();
    const uuids = try allocator.alloc(UUID, num_uuids);
    defer allocator.free(uuids);

    // Generate UUIDs
    for (uuids) |*uuid| {
        uuid.* = uuid1();
    }
    for (uuids, 1..) |uuid_1, i| {
        // Check for duplicates
        for (uuids[i..]) |uuid_2| {
            try testing.expect(!std.mem.eql(u8, &uuid_1.bytes, &uuid_2.bytes));
        }
    }
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

test "UUID v6 monotonicity" {
    const num_uuids = 1_000;
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = &arena_allocator.allocator();
    const uuids = try allocator.alloc(UUID, num_uuids);
    defer allocator.free(uuids);

    // Generate UUIDs
    for (uuids) |*uuid| {
        uuid.* = uuid6();
    }
    var i: usize = 0;
    while (i < uuids.len - 1) : (i += 1) {
        try testing.expect(std.mem.lessThan(u8, &uuids[i].bytes, &uuids[i + 1].bytes));
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

test "toInt" {
    const uuid = try fromString("01234567-89ab-cdef-0123-456789abcdef");
    const uuid_int = uuid.toInt();
    try testing.expectEqual(0x0123456789ABCDEF0123456789ABCDEF, uuid_int);
    try testing.expectEqual(0, nil.toInt());
    try testing.expectEqual((1 << 128) - 1, max.toInt());
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

test "Namespaces" {
    // https://www.rfc-editor.org/rfc/rfc9562.html#section-6.6
    const dns_str = namespace.dns.toString();
    const url_str = namespace.url.toString();
    const oid_str = namespace.oid.toString();
    const x500_str = namespace.x500.toString();
    try testing.expectEqualStrings("6ba7b810-9dad-11d1-80b4-00c04fd430c8", &dns_str);
    try testing.expectEqualStrings("6ba7b811-9dad-11d1-80b4-00c04fd430c8", &url_str);
    try testing.expectEqualStrings("6ba7b812-9dad-11d1-80b4-00c04fd430c8", &oid_str);
    try testing.expectEqualStrings("6ba7b814-9dad-11d1-80b4-00c04fd430c8", &x500_str);
}
