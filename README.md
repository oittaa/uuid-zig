# uuid-zig
Universally Unique IDentifiers (UUIDs) [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)

If UUIDs are required for use with any security operation within an application context in any shape or form, then UUIDv4 SHOULD be utilized. Uses `std.crypto.random` to generate UUIDs.

[![CI](https://github.com/oittaa/uuid-zig/actions/workflows/ci.yaml/badge.svg)](https://github.com/oittaa/uuid-zig/actions/workflows/ci.yaml)

## Example

```zig
const std = @import("std");
const Uuid = @import("Uuid.zig");

pub fn main() !void {
    // generate
    const uuid_v1 = Uuid.uuid1();
    std.debug.print("{}\n", .{uuid_v1});

    const uuid_v3 = Uuid.uuid3(Uuid.namespace.dns, "www.example.com");
    std.debug.print("{}\n", .{uuid_v3});

    const uuid_v4 = Uuid.uuid4();
    std.debug.print("{}\n", .{uuid_v4});

    const uuid_v5 = Uuid.uuid5(Uuid.namespace.url, "https://ziglang.org/");
    std.debug.print("{}\n", .{uuid_v5});

    const uuid_v6 = Uuid.uuid6();
    std.debug.print("{}\n", .{uuid_v6});

    const uuid_v7 = Uuid.uuid7();
    std.debug.print("{}\n", .{uuid_v7});

    // parse
    const my_uuid = try Uuid.fromString("017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
    std.debug.print("{}\n", .{my_uuid});
    std.debug.print("{d}\n", .{my_uuid.bytes});
}
```

```
$ zig run example.zig 
843ca0f0-e211-11ef-9b7b-d1c49c4f52c1
5df41881-3aed-3515-88a7-2f4a814cf09e
53ca4995-31be-4398-b2c0-8ad34104f0eb
708762e7-188c-5d58-b008-f4d694f0bf6d
1efe2118-43cb-634c-9fcf-c2765e4be199
0194cb25-b3b2-7b33-ac38-31349ded7498
017f22e2-79b0-7cc3-98c4-dc0c0c07398f
{ 1, 127, 34, 226, 121, 176, 124, 195, 152, 196, 220, 12, 12, 7, 57, 143 }
```

## UUID Version 4
UUIDv4 is meant for generating UUIDs from truly random or pseudorandom numbers.

### UUIDv4 Field and Bit Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           random_a                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          random_a             |  ver  |       random_b        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|var|                       random_c                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           random_c                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `random_a`: The first 48 bits of the layout that can be filled with random data. Occupies bits 0 through 47 (octets 0-5).
- `ver`: The 4-bit version field, set to 0b0100 (4). Occupies bits 48 through 51 of octet 6.
- `random_b`: 12 more bits of the layout that can be filled random data. Occupies bits 52 through 63 (octets 6-7).
- `var`: The 2-bit variant field, set to 0b10. Occupies bits 64 and 65 of octet 8.
- `random_c`: The final 62 bits of the layout immediately following the var field to be filled with random data. Occupies bits 66 through 127 (octets 8-15).

## UUID Version 7
UUIDv7 features a time-ordered value field derived from the widely implemented and well-known Unix Epoch timestamp source, the number of milliseconds since midnight 1 Jan 1970 UTC, leap seconds excluded. Generally, UUIDv7 has improved entropy characteristics over UUIDv1 or UUIDv6.

Monotonicity (each subsequent value being greater than the last) is the backbone of time-based sortable UUIDs. This implementation uses `Method 3` (*Replace Leftmost Random Bits with Increased Clock Precision*) from the RFC and ensures timestamp increments before creating a new UUID.

### UUIDv7 Field and Bit Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           unix_ts_ms                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          unix_ts_ms           |  ver  |       rand_a          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|var|                        rand_b                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            rand_b                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `unix_ts_ms`: 48-bit big-endian unsigned number of the Unix Epoch timestamp in milliseconds. Occupies bits 0 through 47 (octets 0-5).
- `ver`: The 4-bit version field, set to 0b0111 (7). Occupies bits 48 through 51 of octet 6.
- `rand_a`: The additional clock precision available on the system to substitute 12 random bits immediately following the timestamp. Occupies bits 52 through 63 (octets 6-7).
- `var`: The 2-bit variant field, set to 0b10. Occupies bits 64 and 65 of octet 8.
- `rand_b`: The final 62 bits of pseudorandom data to provide uniqueness. Occupies bits 66 through 127 (octets 8-15).
