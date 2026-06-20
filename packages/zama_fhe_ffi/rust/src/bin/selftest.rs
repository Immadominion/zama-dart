//! On-device self-test for the production native crypto wrapper.
//!
//! Exercises the exact C ABI the Dart FFI uses (`zama_ctx_new_generated` →
//! `zama_encrypt` → `zama_test_verify_decrypt`) and checks the round-trip.
//! Cross-compiled to aarch64-linux-android and run via adb, this proves the
//! tfhe-1.5.4 (network-compatible) wrapper works on a real phone.

use std::time::Instant;

use zama_fhe_native::{
    zama_bytes_free, zama_ctx_free, zama_ctx_new_generated, zama_encrypt,
    zama_test_verify_decrypt, ByteBuf,
};

fn main() {
    println!(
        "== zama_fhe_native selftest ({} / {}) ==",
        std::env::consts::ARCH,
        std::env::consts::OS
    );

    // (value, type id). Covers small ints, ebool, eaddress (160-bit) and
    // euint256 (full width) — values fit in u128 here for easy comparison.
    let cases: Vec<(u128, u8)> = vec![
        (42, 5),                                   // euint64
        (7, 4),                                    // euint32
        (1, 0),                                    // ebool
        (0x00aa_bbcc_dd00_1122_3344_5566_u128, 7), // eaddress (160-bit value)
        (0xdead_beef_cafe_u128, 8),                // euint256
    ];
    let types: Vec<u8> = cases.iter().map(|(_, t)| *t).collect();
    let n = cases.len();

    let mut values_be32 = vec![0u8; n * 32];
    for (i, (v, _)) in cases.iter().enumerate() {
        // 32-byte big-endian: value in the low 16 bytes.
        values_be32[i * 32 + 16..i * 32 + 32].copy_from_slice(&v.to_be_bytes());
    }
    let metadata = vec![0u8; 92];

    unsafe {
        let t = Instant::now();
        let ctx = zama_ctx_new_generated(256);
        if ctx.is_null() {
            eprintln!("FAIL: ctx_new_generated returned null");
            std::process::exit(1);
        }
        println!("[setup]   keygen + CRS: {} ms", t.elapsed().as_millis());

        let mut out = ByteBuf { ptr: std::ptr::null_mut(), len: 0, cap: 0 };
        let t = Instant::now();
        let rc = zama_encrypt(
            ctx,
            values_be32.as_ptr(),
            types.as_ptr(),
            n,
            metadata.as_ptr(),
            metadata.len(),
            &mut out,
        );
        if rc != 0 {
            eprintln!("FAIL: zama_encrypt rc={rc}");
            std::process::exit(1);
        }
        println!(
            "[encrypt] {} inputs in {} ms, inputProof {} bytes",
            n,
            t.elapsed().as_millis(),
            out.len
        );

        let mut decoded = vec![0u8; n * 32];
        let t = Instant::now();
        let cnt = zama_test_verify_decrypt(
            ctx,
            out.ptr,
            out.len,
            types.as_ptr(),
            n,
            metadata.as_ptr(),
            metadata.len(),
            decoded.as_mut_ptr(),
            n,
        );
        if cnt < 0 {
            eprintln!("FAIL: zama_test_verify_decrypt rc={cnt}");
            std::process::exit(1);
        }

        // Parse the low 128 bits of each 32-byte BE slot back to a u128.
        let got: Vec<u128> = (0..n)
            .map(|i| {
                let mut b = [0u8; 16];
                b.copy_from_slice(&decoded[i * 32 + 16..i * 32 + 32]);
                u128::from_be_bytes(b)
            })
            .collect();
        println!(
            "[verify]  verify_and_expand + decrypt: {} ms -> {:?}",
            t.elapsed().as_millis(),
            got
        );

        zama_bytes_free(out);
        zama_ctx_free(ctx);

        let want: Vec<u128> = cases.iter().map(|(v, _)| *v).collect();
        let ok = got == want;
        println!("RESULT: {}", if ok { "OK" } else { "MISMATCH" });
        if !ok {
            std::process::exit(1);
        }
    }
}
