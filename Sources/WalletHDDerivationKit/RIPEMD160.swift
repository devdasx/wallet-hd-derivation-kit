import Foundation

// RIPEMD-160 is retained here because Apple CryptoKit does not expose it. This
// compact implementation follows ISO/IEC 10118-3 and is covered by published
// RIPEMD-160 and Bitcoin HASH160 vectors in the test suite.
enum RIPEMD160 {
    private static let r1: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]

    private static let r2: [Int] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]

    private static let s1: [UInt32] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]

    private static let s2: [UInt32] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]

    static func hash(_ input: [UInt8]) -> [UInt8] {
        var message = input
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 { message.append(0) }
        message += withUnsafeBytes(of: bitLength.littleEndian, Array.init)

        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xefcdab89
        var h2: UInt32 = 0x98badcfe
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xc3d2e1f0

        for offset in stride(from: 0, to: message.count, by: 64) {
            var x = [UInt32](repeating: 0, count: 16)
            for index in 0..<16 {
                let start = offset + index * 4
                x[index] = UInt32(message[start])
                    | UInt32(message[start + 1]) << 8
                    | UInt32(message[start + 2]) << 16
                    | UInt32(message[start + 3]) << 24
            }

            var al = h0, bl = h1, cl = h2, dl = h3, el = h4
            var ar = h0, br = h1, cr = h2, dr = h3, er = h4
            for round in 0..<80 {
                let left = rotateLeft(
                    al &+ f(round, bl, cl, dl) &+ x[r1[round]] &+ k1(round),
                    by: s1[round]
                ) &+ el
                al = el; el = dl; dl = rotateLeft(cl, by: 10); cl = bl; bl = left

                let right = rotateLeft(
                    ar &+ f(79 - round, br, cr, dr) &+ x[r2[round]] &+ k2(round),
                    by: s2[round]
                ) &+ er
                ar = er; er = dr; dr = rotateLeft(cr, by: 10); cr = br; br = right
            }

            let temporary = h1 &+ cl &+ dr
            h1 = h2 &+ dl &+ er
            h2 = h3 &+ el &+ ar
            h3 = h4 &+ al &+ br
            h4 = h0 &+ bl &+ cr
            h0 = temporary
        }

        return [h0, h1, h2, h3, h4].flatMap { withUnsafeBytes(of: $0.littleEndian, Array.init) }
    }

    private static func f(_ round: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        switch round {
        case 0..<16: x ^ y ^ z
        case 16..<32: (x & y) | (~x & z)
        case 32..<48: (x | ~y) ^ z
        case 48..<64: (x & z) | (y & ~z)
        default: x ^ (y | ~z)
        }
    }

    private static func k1(_ round: Int) -> UInt32 {
        switch round {
        case 0..<16: 0x00000000
        case 16..<32: 0x5a827999
        case 32..<48: 0x6ed9eba1
        case 48..<64: 0x8f1bbcdc
        default: 0xa953fd4e
        }
    }

    private static func k2(_ round: Int) -> UInt32 {
        switch round {
        case 0..<16: 0x50a28be6
        case 16..<32: 0x5c4dd124
        case 32..<48: 0x6d703ef3
        case 48..<64: 0x7a6d76e9
        default: 0x00000000
        }
    }

    private static func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }
}
