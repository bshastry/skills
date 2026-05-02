// ct-fuzz Rust harness, dudect-style.
//
// Reads "<target> <samples>\n" on stdin per run; emits "<class> <ns>\n"
// per timed sample, then "DONE\n". Uses Instant::now() for timing.

use std::io::{self, BufRead, BufWriter, Write};
use std::time::Instant;

use rand::{rngs::StdRng, RngCore, SeedableRng};

mod targets;

pub type TargetFn = Box<dyn Fn(&[u8], &[u8])>;

pub struct TargetSpec {
    pub func: TargetFn,
    pub secret_len: usize,
    pub public_len: usize,
    pub inner: usize,
}

fn build_targets() -> Vec<(&'static str, TargetSpec)> {
    targets::register_all()
}

fn run_one<W: Write>(
    out: &mut BufWriter<W>,
    spec: &TargetSpec,
    n: usize,
) -> io::Result<()> {
    let mut rng = StdRng::from_entropy();

    // Public input: fixed 0xAA fill (matching Go harness convention).
    let mut public_buf = vec![0xAAu8; spec.public_len];
    let mut secret_buf = vec![0u8; spec.secret_len];
    let fixed_a = vec![0xAAu8; spec.secret_len];

    // Pre-generate class selector + random secrets.
    let mut class_bytes = vec![0u8; n];
    rng.fill_bytes(&mut class_bytes);
    let mut random_pool = vec![0u8; n * spec.secret_len];
    rng.fill_bytes(&mut random_pool);

    // Warmup.
    for i in 0..2048 {
        secret_buf.copy_from_slice(
            &random_pool[(i % n) * spec.secret_len..(i % n + 1) * spec.secret_len],
        );
        (spec.func)(&public_buf, &secret_buf);
    }
    // Public stays at 0xAA (no-op).
    let _ = &mut public_buf;

    for i in 0..n {
        let class = if class_bytes[i] & 1 == 0 {
            secret_buf.copy_from_slice(&fixed_a);
            b'A'
        } else {
            secret_buf.copy_from_slice(
                &random_pool[i * spec.secret_len..(i + 1) * spec.secret_len],
            );
            b'B'
        };
        let t0 = Instant::now();
        for _ in 0..spec.inner {
            (spec.func)(&public_buf, &secret_buf);
        }
        let t1 = Instant::now();
        let ns = t1.duration_since(t0).as_nanos() as u64;
        writeln!(out, "{} {}", class as char, ns)?;
    }
    writeln!(out, "DONE")?;
    out.flush()?;
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let targets_map = build_targets();

    if args.len() >= 2 && args[1] == "list" {
        for (name, spec) in &targets_map {
            println!(
                "{}\tsecret={}\tpublic={}\tinner={}",
                name, spec.secret_len, spec.public_len, spec.inner
            );
        }
        return Ok(());
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            eprintln!("ct-fuzz: bad command {:?}", line);
            continue;
        }
        let name = parts[0];
        let n: usize = match parts[1].parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("ct-fuzz: bad sample count {:?}", parts[1]);
                continue;
            }
        };
        let spec = match targets_map.iter().find(|(n, _)| *n == name) {
            Some((_, s)) => s,
            None => {
                eprintln!("ct-fuzz: unknown target {:?}", name);
                continue;
            }
        };
        run_one(&mut out, spec, n)?;
    }
    Ok(())
}
