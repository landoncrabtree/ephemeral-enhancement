<?php
/*
 * Generate mcrypt test vectors for Python parity testing.
 * Outputs JSON with encrypt results for known plaintext/key/IV combos.
 */

$vectors = [];

// Helper: encrypt and return hex
function make_vector($algo, $mode, $key, $iv, $plaintext, $label) {
    $ct = @mcrypt_encrypt($algo, $key, $plaintext, $mode, $iv);
    if ($ct === false) {
        return null;
    }
    return [
        'label' => $label,
        'algo' => $algo,
        'mode' => $mode,
        'key_hex' => bin2hex($key),
        'iv_hex' => $iv !== null ? bin2hex($iv) : null,
        'plaintext_hex' => bin2hex($plaintext),
        'ciphertext_hex' => bin2hex($ct),
    ];
}

// --- rijndael-128 (AES) ---
$key16 = "0123456789abcdef";
$iv16 = str_repeat("\x00", 16);
$pt16 = "Hello World!!!!!" ;  // 16 bytes exactly

$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, $key16, "", $pt16, "aes128-ecb-exact-block");
if ($v) $vectors[] = $v;

$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC, $key16, $iv16, $pt16, "aes128-cbc-zero-iv");
if ($v) $vectors[] = $v;

$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC, $key16, $key16, $pt16, "aes128-cbc-key-as-iv");
if ($v) $vectors[] = $v;

// Short plaintext (should be zero-padded by mcrypt)
$pt_short = "Hello";
$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, $key16, "", $pt_short, "aes128-ecb-short-pt");
if ($v) $vectors[] = $v;

// CFB mode
$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CFB, $key16, $iv16, $pt16, "aes128-cfb-zero-iv");
if ($v) $vectors[] = $v;

// OFB mode
$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_OFB, $key16, $iv16, $pt16, "aes128-ofb-zero-iv");
if ($v) $vectors[] = $v;

// nOFB mode
$v = make_vector(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_NOFB, $key16, $iv16, $pt16, "aes128-nofb-zero-iv");
if ($v) $vectors[] = $v;

// --- DES ---
$key8 = "abcdefgh";
$iv8 = str_repeat("\x00", 8);
$pt8 = "TestData";  // 8 bytes

$v = make_vector(MCRYPT_DES, MCRYPT_MODE_ECB, $key8, "", $pt8, "des-ecb-exact-block");
if ($v) $vectors[] = $v;

$v = make_vector(MCRYPT_DES, MCRYPT_MODE_CBC, $key8, $iv8, $pt8, "des-cbc-zero-iv");
if ($v) $vectors[] = $v;

// Short key for DES (should fail or be padded)
$v = make_vector(MCRYPT_DES, MCRYPT_MODE_ECB, "abc", "", $pt8, "des-ecb-short-key");
if ($v) $vectors[] = $v;

// --- TripleDES ---
$key24 = "0123456789abcdef01234567";
$v = make_vector(MCRYPT_3DES, MCRYPT_MODE_ECB, $key24, "", $pt8, "3des-ecb");
if ($v) $vectors[] = $v;

$v = make_vector(MCRYPT_3DES, MCRYPT_MODE_CBC, $key24, $iv8, $pt8, "3des-cbc-zero-iv");
if ($v) $vectors[] = $v;

// --- Blowfish ---
$v = make_vector(MCRYPT_BLOWFISH, MCRYPT_MODE_ECB, $key16, "", $pt8, "blowfish-ecb");
if ($v) $vectors[] = $v;

$v = make_vector(MCRYPT_BLOWFISH, MCRYPT_MODE_CBC, $key16, $iv8, $pt8, "blowfish-cbc-zero-iv");
if ($v) $vectors[] = $v;

// --- Twofish ---
$v = make_vector(MCRYPT_TWOFISH, MCRYPT_MODE_ECB, $key16, "", $pt16, "twofish-ecb");
if ($v) $vectors[] = $v;

// --- CAST-128 ---
$v = make_vector(MCRYPT_CAST_128, MCRYPT_MODE_ECB, $key16, "", $pt8, "cast128-ecb");
if ($v) $vectors[] = $v;

// --- Serpent ---
$v = make_vector(MCRYPT_SERPENT, MCRYPT_MODE_ECB, $key16, "", $pt16, "serpent-ecb");
if ($v) $vectors[] = $v;

// --- XTEA ---
$v = make_vector(MCRYPT_XTEA, MCRYPT_MODE_ECB, $key16, "", $pt8, "xtea-ecb");
if ($v) $vectors[] = $v;

// --- RC4 (arcfour) ---
$v = make_vector(MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, $key16, "", $pt16, "arcfour-stream");
if ($v) $vectors[] = $v;

// Short key for arcfour
$v = make_vector(MCRYPT_ARCFOUR, MCRYPT_MODE_STREAM, "key", "", "Hello World", "arcfour-stream-short-key");
if ($v) $vectors[] = $v;

// --- rijndael-256 ---
$key32 = "0123456789abcdef0123456789abcdef";
$iv32 = str_repeat("\x00", 32);
$pt32 = "Hello World 1234Hello World 1234";
$v = make_vector(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB, $key32, "", $pt32, "rijndael256-ecb");
if ($v) $vectors[] = $v;

$v = make_vector(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC, $key32, $iv32, $pt32, "rijndael256-cbc-zero-iv");
if ($v) $vectors[] = $v;

// --- GOST ---
$v = make_vector(MCRYPT_GOST, MCRYPT_MODE_ECB, $key32, "", $pt8, "gost-ecb");
if ($v) $vectors[] = $v;

echo json_encode($vectors, JSON_PRETTY_PRINT) . "\n";
