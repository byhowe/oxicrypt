extern crate std;

use std::io::stdin;
use std::io::stdout;
use std::io::Write;

use oxicrypt::hmac;
use oxicrypt::sha::Implementation;

fn main() -> std::io::Result<()>
{
  let mut sout = stdout();
  let sin = stdin();

  let mut buffer = String::new();

  sout.write_all(b"Enter key: ")?;
  sout.flush()?;
  sin.read_line(&mut buffer)?;

  let i = Implementation::fastest_rt();
  let mut h = hmac::HmacSha256::with_key(i, &buffer[0 .. buffer.len() - 1]);

  buffer.clear();

  sout.write_all(b"Enter data: ")?;
  sout.flush()?;
  sin.read_line(&mut buffer)?;

  h.update(i, &buffer[0 .. buffer.len() - 1]);
  let digest = h.finish(i);
  let encoded = hex::encode(&digest);
  sout.write_all(encoded.as_bytes())?;
  sout.write_all(b"\n")?;
  sout.flush()?;

  Ok(())
}
