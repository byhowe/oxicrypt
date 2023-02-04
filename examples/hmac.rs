extern crate std;

use std::io::stdin;
use std::io::stdout;
use std::io::Write;

use oxicrypt::hmac::Hmac;
use oxicrypt::sha::Sha256;
use oxicrypt::digest::Digest;

fn main() -> std::io::Result<()>
{
    let mut sout = stdout();
    let sin = stdin();

    let mut buffer = String::new();

    sout.write_all(b"Enter key: ")?;
    sout.flush()?;
    sin.read_line(&mut buffer)?;

    let mut h = Hmac::<Sha256>::with_key(buffer[0..buffer.len() - 1].as_bytes());

    buffer.clear();

    sout.write_all(b"Enter data: ")?;
    sout.flush()?;
    sin.read_line(&mut buffer)?;

    h.update(buffer[0..buffer.len() - 1].as_bytes());
    let digest = h.finish();
    let encoded = hex::encode(digest);
    sout.write_all(encoded.as_bytes())?;
    sout.write_all(b"\n")?;
    sout.flush()?;

    Ok(())
}
