// ct-fuzz Rust harness, dudect-style.
//
// Reads "<target> <samples>\n" on stdin per run; emits "<class> <ns>\n"
// per timed sample, then "DONE\n". Uses Instant::now() for timing.

use std::io::{self, BufRead, BufWriter, Write};

use rand::{rngs::StdRng, RngCore, SeedableRng};

mod targets;

/// Cycle-accurate timer: lfence; rdtscp; lfence. amd64 only.
///
/// rdtscp itself partially serializes against earlier instructions but
/// not against later ones; the lfences give strict ordering. Overhead
/// is ~30 cycles vs ~10 ns for Instant::now() — the difference between
/// "measurable" and "drowned in timer noise" for ns-fast crypto ops.
#[inline]
fn rdtscp_lfence() -> u64 {
    use std::arch::x86_64::{__rdtscp, _mm_lfence};
    let mut aux: u32 = 0;
    unsafe {
        _mm_lfence();
        let t = __rdtscp(&mut aux as *mut u32);
        _mm_lfence();
        t
    }
}

pub type TargetFn = Box<dyn Fn(&[u8], &[u8])>;

// Split-mode callbacks. prep is untimed (state stashed in closure-captured
// vars); measure is the timed call. Use FnMut so prep can mutate cells.
pub type PrepFn = Box<dyn FnMut(&[u8])>;
pub type MeasureFn = Box<dyn FnMut(&[u8])>;

pub struct TargetSpec {
    pub func: Option<TargetFn>,
    pub prep: Option<PrepFn>,
    pub measure: Option<MeasureFn>,
    pub secret_len: usize,
    pub public_len: usize,
    pub inner: usize,
}

impl TargetSpec {
    pub fn whole(secret_len: usize, public_len: usize, inner: usize, func: TargetFn) -> Self {
        TargetSpec {
            func: Some(func),
            prep: None,
            measure: None,
            secret_len,
            public_len,
            inner,
        }
    }
    pub fn split(
        secret_len: usize,
        public_len: usize,
        inner: usize,
        prep: PrepFn,
        measure: MeasureFn,
    ) -> Self {
        TargetSpec {
            func: None,
            prep: Some(prep),
            measure: Some(measure),
            secret_len,
            public_len,
            inner,
        }
    }
}

fn build_targets() -> Vec<(&'static str, TargetSpec)> {
    targets::register_all()
}

fn run_one<W: Write>(
    out: &mut BufWriter<W>,
    spec: &mut TargetSpec,
    n: usize,
) -> io::Result<()> {
    let mut rng = StdRng::from_entropy();

    // Public input: fixed 0xAA fill (matching Go harness convention).
    let public_buf = vec![0xAAu8; spec.public_len];
    let mut secret_buf = vec![0u8; spec.secret_len];
    let fixed_a = vec![0xAAu8; spec.secret_len];

    // Pre-generate class selector + random secrets.
    let mut class_bytes = vec![0u8; n];
    rng.fill_bytes(&mut class_bytes);
    let mut random_pool = vec![0u8; n * spec.secret_len];
    rng.fill_bytes(&mut random_pool);

    let split = spec.func.is_none();

    // Warmup.
    for i in 0..2048 {
        secret_buf.copy_from_slice(
            &random_pool[(i % n) * spec.secret_len..(i % n + 1) * spec.secret_len],
        );
        if split {
            (spec.prep.as_mut().unwrap())(&secret_buf);
            (spec.measure.as_mut().unwrap())(&public_buf);
        } else {
            (spec.func.as_ref().unwrap())(&public_buf, &secret_buf);
        }
    }

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
        if split {
            // Prep runs OUTSIDE the timing window — key schedule, dispatch,
            // allocator. State stashed in closure-captured cells; measure reads it.
            (spec.prep.as_mut().unwrap())(&secret_buf);
            let t0 = rdtscp_lfence();
            for _ in 0..spec.inner {
                (spec.measure.as_mut().unwrap())(&public_buf);
            }
            let t1 = rdtscp_lfence();
            writeln!(out, "{} {}", class as char, t1.wrapping_sub(t0))?;
        } else {
            let t0 = rdtscp_lfence();
            for _ in 0..spec.inner {
                (spec.func.as_ref().unwrap())(&public_buf, &secret_buf);
            }
            let t1 = rdtscp_lfence();
            writeln!(out, "{} {}", class as char, t1.wrapping_sub(t0))?;
        }
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

    let mut targets_map = targets_map;
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
        let name = parts[0].to_string();
        let n: usize = match parts[1].parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("ct-fuzz: bad sample count {:?}", parts[1]);
                continue;
            }
        };
        let spec = match targets_map.iter_mut().find(|(n, _)| *n == name) {
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
