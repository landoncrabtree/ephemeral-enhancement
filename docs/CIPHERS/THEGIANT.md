# The Giant

## TG-1

    Cipher type: Barcode
    Solved by: /u/TheCoolDoc

PLAIN TEXT

    The mountain must be searched for the frozen one.

 
## TG-2

    Cipher type: Periodic table & chemical symbol
    Solved by: /u/Shaiza_Balls

PLAIN TEXT

    In the cell below the waves is where honor suffers.

 
## TG-3

    Cipher type: Simplified Lorenz
    K-wheel = 9 & S-wheel = 4
    Solved by: /u/Munki

PLAIN TEXT

    When finished we will return to the house and the infinite

 
## TG-4 (Unsolved)

    Cipher type: Unknown (likely mcrypt-based symmetric cipher)
    Key: TheGiant (per waterkh/BlackOpsCiphers)
    Status: UNSOLVED — key is known but cipher type/algorithm is unknown

CIPHER TEXT (source of truth — see "Transcription" below)

    kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvlqkZil0KIAXAzP1U1uy1BE4U
    fPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wn
    dJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1
    JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1

192 base64 characters, no padding, decoding to 144 bytes (9 x 16-byte blocks).
The line breaks are texture layout only — concatenate them, and note the string
contains no spaces.

### Transcription

The original texture is `i_mtl_p7_zm_the_giant_cipher_01_c`, set in Franklin
Gothic URW Comp Book, where `0`/`O` and `I`/`l` are visually confusable. Getting
these wrong changes the decrypted bytes, so the reading is not a matter of
preference.

The text above is the output of **[`glyphid/`](../../glyphid/)**, which resolves
those pairs by measuring glyph geometry from pixel coverage — stem width for
`I` vs `l` (they differ by 10.1% in the outlines, 0.32 px on the texture) and
moment aspect ratio for `0` vs `O`. Coverage integrals are invariant to the
unknown 2012-era rasteriser's antialiasing, so this is a direct measurement
rather than a guess or a re-render comparison.

The authoritative lines live in
[`glyphid/der_riese_lines.txt`](../../glyphid/der_riese_lines.txt) and are
byte-identical to the block above.

It corrects **four glyphs** relative to waterkh's BlackOpsCiphers transcription:

| Position | waterkh | glyphid | Context |
|---|---|---|---|
| 3 | `I` | `l` | `kCm[l]gFi6GU` |
| 31 | `I` | `l` | `oCFTCv[l]qkZil0` |
| 36 | `I` | `l` | `vlqkZi[l]0KIAXA` |
| 64 | `0` | `O` | `fpKmmL[O]bjYnQN` |

Earlier brute-force results recorded against the waterkh string therefore
targeted the wrong ciphertext and were all retired — see `ATTEMPTS.md`.

### Statistical profile

Every metric sits inside the 95% envelope for random data of the same length
(144 bytes): H(bytes) 6.77, chi-squared/df 0.90 over bytes, IC 0.82, lag-1
autocorrelation -0.047. That is consistent with any modern block cipher, and
also with a *transposed* modern ciphertext — a transposition over a
high-entropy payload is provably invisible to these statistics, so they cannot
rule a permutation layer in or out.

Live brute-force coverage: **https://ee.landon.pw**

 
## TG-5

    Cipher type: Enigma M3
    Reflector: UKW B
    Key settings: WAD
    Ring settings: AAD
    Rotors: 123
    Plug board settings: PO ML IU KJ NH YT GB VF RE DC
    Solved by: /u/Randomiser

PLAIN TEXT

    A city of fire surrounds the warrior the last of his kind
