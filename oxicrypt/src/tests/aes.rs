use crate::aes::Aes128;

#[test]
fn test_aes()
{
  let key = hex::decode("00000000000000000000000000000000").unwrap();
  let plaintext = hex::decode("f34481ec3cc627bacd5dc3fb08f273e6").unwrap();
  let ciphertext = hex::decode("0336763e966d92595a567cc9ce537f5e").unwrap();
  let mut block = plaintext.clone();
  let mut ctx = Aes128::new();

  ctx.set_encrypt_key(&key).unwrap();
  ctx.encrypt(&mut block).unwrap();
  assert_eq!(block, ciphertext);

  ctx.set_decrypt_key(&key).unwrap();
  ctx.decrypt(&mut block).unwrap();
  assert_eq!(block, plaintext);
}
