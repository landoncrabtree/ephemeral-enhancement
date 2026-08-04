"""
End-to-end tests using real confirmed Black Ops 3 cipher solutions.

Each test replicates a known decryption chain step-by-step, verifying that
the full pipeline produces the expected plaintext from the original ciphertext.
"""

from __future__ import annotations

import base64

import pytest

from stages.mcrypt_registry import get_stage_info
from stages.mcrypt_wrapper import McryptHandleCache, mcrypt_decrypt
from stages.polyalpha import beaufort_decrypt


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def cache():
    return McryptHandleCache()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _strip_mcrypt_output(data: bytes) -> bytes:
    """Strip null bytes and trailing control chars (< 0x20) from mcrypt output."""
    data = data.rstrip(b"\x00")
    while data and data[-1] < 0x20:
        data = data[:-1]
    return data


# ---------------------------------------------------------------------------
# Test 1: beaufort52 > b64 > rc2-ecb > reverse > b64 > rijndael-256-ecb
#   OkEeZH... -> beaufort52(ZOMBIES) -> b64 -> rc2-ecb(Zombies) -> reverse
#   -> b64 -> rijndael-256-ecb(Zombies) -> "The many worlds are now one."
# ---------------------------------------------------------------------------

MULTI_CT = (
    "OkEeZHnifuMdYB1IbHyAfb0g2FJzrVmfkKcSbKrpQGvhQ0/bvu76RdnGy/WtT7T3"
)
MULTI_PLAINTEXT = "The many worlds are now one."


def test_beaufort52_rc2_rijndael(cache):
    # Step 1: beaufort52 with key ZOMBIES
    after_beaufort = beaufort_decrypt(MULTI_CT, "ZOMBIES", alpha52=True)
    assert after_beaufort is not None

    # Step 2: base64 decode
    raw = base64.b64decode(after_beaufort)

    # Step 3: rc2-ecb decrypt
    after_rc2 = mcrypt_decrypt(
        "rc2", "ecb", b"Zombies", b"", raw, handle_cache=cache
    )
    assert after_rc2 is not None
    after_rc2_text = _strip_mcrypt_output(after_rc2).decode("ascii")

    # Step 4: reverse
    reversed_text = after_rc2_text[::-1]

    # Step 5: base64 decode
    raw2 = base64.b64decode(reversed_text)

    # Step 6: rijndael-256-ecb decrypt
    result = mcrypt_decrypt(
        "rijndael-256", "ecb", b"Zombies", b"", raw2, handle_cache=cache
    )
    assert result is not None
    text = _strip_mcrypt_output(result).decode("utf-8")
    assert text == MULTI_PLAINTEXT


# ---------------------------------------------------------------------------
# Test 3: b64 > loki97-cfb (single stage)
#   Long b64 ciphertext -> b64 -> loki97-cfb(Zombies, IV="0"*16)
#   -> "August, 1946. OSS report final T-7..."
# ---------------------------------------------------------------------------
# Test 2: b64 > rc2-cfb > reverse > hex > blowfish-cfb > b64 > loki97-cfb
#   Long b64 ciphertext -> b64 -> rc2-cfb(Zombies, IV="0"*8) -> reverse
#   -> hex decode -> blowfish-cfb(Zombies, IV="0"*8)
#   -> b64 -> loki97-cfb(Zombies, IV="0"*16)
#   -> "August, 1946. OSS report final T-7..."
# ---------------------------------------------------------------------------

THREE_MCRYPT_CT = (
    "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"
)

OSS_PLAINTEXT = (
    "August, 1946. OSS report final T-7. All of the Group 935 and "
    "Division 9 facilities we were able to procure have been dismantled "
    "and crated. We have 215 scientists heading back to the United States "
    "for orientation.\nJuly, 1947. OSS asset transfer request. We are "
    "requesting that Dr. Shuster be transferred to Broomstick and the "
    "Titan Project because of extensive intimacy with Group 935\u2019s long "
    "range rockets. If approved, we will have him onsite at White Sands "
    "for the first Titan Project test as an observer. As you know it is "
    "imperative that we advance Titan quickly and reach the anomaly "
    "before the Russians."
)


def test_3mcrypt_chain(cache):
    """b64 > rc2-cfb > reverse > hex > blowfish-cfb > b64 > loki97-cfb."""
    ct = THREE_MCRYPT_CT.replace(" ", "").replace("\n", "")
    key = b"Zombies"

    # Step 1: base64 decode
    raw = base64.b64decode(ct)

    # Step 2: rc2-cfb (IV = "0" * 8)
    s1 = mcrypt_decrypt("rc2", "cfb", key, b"0" * 8, raw, handle_cache=cache)
    assert s1 is not None
    s1_text = _strip_mcrypt_output(s1[: len(raw)]).decode("ascii")
    # Output should be hex string
    assert all(c in "0123456789abcdef" for c in s1_text)

    # Step 3: reverse
    rev = s1_text[::-1]

    # Step 4: hex decode
    hex_bytes = bytes.fromhex(rev)

    # Step 5: blowfish-cfb (IV = "0" * 8)
    s3 = mcrypt_decrypt("blowfish", "cfb", key, b"0" * 8, hex_bytes, handle_cache=cache)
    assert s3 is not None
    s3_text = _strip_mcrypt_output(s3[: len(hex_bytes)]).decode("ascii")
    # Output should be base64
    assert len(s3_text) > 100

    # Step 6: base64 decode
    s4 = base64.b64decode(s3_text)

    # Step 7: loki97-cfb (IV = "0" * 16)
    s5 = mcrypt_decrypt("loki97", "cfb", key, b"0" * 16, s4, handle_cache=cache)
    assert s5 is not None
    text = _strip_mcrypt_output(s5[: len(s4)]).decode("utf-8")

    assert text.startswith("August, 1946. OSS report final T-7.")
    assert text.endswith("before the Russians.")


# ---------------------------------------------------------------------------
# Test 3: hex > xtea-cfb > reverse > caesar(shift=6)
#   Hex ciphertext -> hex decode -> xtea-cfb(Zombies, IV=null)
#   -> reverse -> caesar(shift=6)
#   -> "Now that the many worlds are one..."
# ---------------------------------------------------------------------------

XTEA_HEX_CT = (
    "4521d3f287d5d75616be3fa56852a08234104a78448c2e5a2e5ee6ed7cad795671"
    "e6129fec7151d875a0ab9ce7c1b7eb2319d23e264479b5826645b0f6b6d648eb85"
    "9aa9df6a5cce921b64a2ad0a1f12fbe4d7cd008bd02893156462b1ebed006862f7"
    "665a152cc39970ee0aaade5465d2920665e979b9dc6ef6041b8f06802693275418"
    "cfb8034ff29bf0f77a3f4f7d84fe63786ede39533d1747c9ff5c0eb3ad5731d09d"
    "eb68a36e9469b04b86ea484bf3cb39b1ad19e0d05114f593c59ea161a1ada1a97f"
    "dd65866c6389fddf8cf7285df6"
)

XTEA_PLAINTEXT_BODY = (
    "Now that the many worlds are one, it has all reset. There are no "
    "Apothicon, Keepers, or 115 knocking around to cause trouble."
)


def _caesar_shift(text: str, shift: int) -> str:
    """Apply a caesar shift (decryption direction)."""
    result = []
    for c in text:
        if "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
        elif "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
        else:
            result.append(c)
    return "".join(result)


def test_xtea_reverse_caesar(cache):
    """hex > xtea-cfb (IV prepended) > reverse > caesar(shift=6)."""
    raw = bytes.fromhex(XTEA_HEX_CT.replace(" ", "").replace("\n", ""))
    key = b"Zombies"

    # Step 1: xtea-cfb with prepended IV (first iv_size bytes = IV)
    iv_size = get_stage_info("xtea-cfb").iv_size
    iv = raw[:iv_size]
    ct = raw[iv_size:]
    s1 = mcrypt_decrypt("xtea", "cfb", key, iv, ct, handle_cache=cache)
    assert s1 is not None
    s1_text = _strip_mcrypt_output(s1[: len(ct)]).decode("ascii", errors="replace")

    # Step 2: reverse
    rev = s1_text[::-1]

    # Step 3: caesar shift 6
    plaintext = _caesar_shift(rev, 6)

    assert XTEA_PLAINTEXT_BODY in plaintext
    assert "focus on the children" in plaintext


def test_xtea_zero_string_iv_recovers_signature(cache):
    """IV = "0"*8 (not prepended) recovers the full text incl. the en-dash sign-off."""
    from stages.common import combined_score

    raw = bytes.fromhex(XTEA_HEX_CT.replace(" ", "").replace("\n", ""))
    iv_size = get_stage_info("xtea-cfb").iv_size

    s1 = mcrypt_decrypt("xtea", "cfb", b"Zombies", b"0" * iv_size, raw,
                        handle_cache=cache)
    assert s1 is not None
    text = _strip_mcrypt_output(s1[: len(raw)]).decode("utf-8")
    plaintext = _caesar_shift(text[::-1], 6)

    # CFB is self-synchronising: only the first block depends on the IV, and
    # `reverse` moves it to the tail, so a wrong IV silently clips the sign-off.
    assert XTEA_PLAINTEXT_BODY in plaintext
    assert plaintext.rstrip().endswith("better place. \u2013M")

    # The en dash must not push the score below the printable cutoff
    assert combined_score(plaintext.encode("utf-8")) > 1.5


# ---------------------------------------------------------------------------
# Test 4: hex > reverse > hex > blowfish-compat-cfb > b64
#   Double-hex ciphertext -> hex -> reverse -> hex
#   -> blowfish-compat-cfb(Zombies, IV="0"*8) -> b64
#   -> "Final entry: I have run out of pages for this journal..."
# ---------------------------------------------------------------------------

# Outer hex encodes inner hex digits; inner hex (after reverse) decodes to
# the blowfish ciphertext.  The outer hex string has odd length (2303 chars
# after stripping CRLF), so a leading "0" is prepended before reversing.
DOUBLE_HEX_CT = (
    "386339373865356533653764333534353364376566653665353432633365353433"
    "366331373235633761633136626137653232666639386531323636333464303163"
    "376237363663363237663733373264653431613836633266653137353034623833"
    "323362383866653363353364626261656332323165373566653766613435353430"
    "363363376230313863666234353237623231613236363561653039333333396138"
    "343831633366653232353166396366313230613138316331343639336566383339"
    "313966623561666566316166613833376431383635643936326335373933306465"
    "613163316138656665663064303830646130393336663265323762616666373535"
    "653066353239653638646366373730353232383439363837616438616164393863"
    "623038633634396538343137373964346138666233313234643630666161373164"
    "326565383066323561656466363566656430343464303336336239386564393938"
    "303830663632356435663132626635323339663333343837333465376436643663"
    "656530663262333332616639316139623934353636653133613763326238353234"
    "353035386462656265656262353834383138626339313732376236363831373463"
    "336263343537326431376433343734633239303461616436333565623336356263"
    "393830333139663966663535323565363965383632306365616464333665633038"
    "393430303839373839326466353036643665373730383633336438633532656534"
    "366332396637376339336435376232333839656463303936623330393235303133"
    "656665326536613333356530376362326161643038643832623937623538646164"
    "636635343334366333386362653236386165626235343262346661306132353565"
    "636332346163613634646239333865383036326265316638393063393639383837"
    "623335626431663239663133336431313333643137623539373063666461646531"
    "633233643934653036316464326665363635393466666332636636623336383334"
    "353438643635356130356134373138316130636262663639303532373832356131"
    "633639373230613831363232323939616234656232376134636161646238626561"
    "663563373263366362393138353439363433636330636537373738633265303330"
    "303431333934633332383532636439393963643561356263313538636334336462"
    "333564393562313039353938613837393063313439306334656635343763373532"
    "363933613639323335643735616334306466646163663733623765383063333133"
    "396365626135353838316364323431666261646330643664306562366136356161"
    "653630306132616164646438306233633064646165313063653566333838616637"
    "303536643766313462353833326461663738386130663365633461623237613936"
    "353463383430363761376135626439636333663839623364333164313965383364"
    "623833366539616438656230363963303237653537336663616663323965663934"
    "356339366461356234636439396230353337306534616437366636643466643166"
    "623837356630666537336530376131623437316163353038313863613161656237"
    "333865323962616664623161336166366536333161623461386132633864623438"
    "396165386333393739633533393732363932396362626261626365653366316631"
    "323132356539383464313061396331636434646134663131373037303065316232"
    "653064636432616634313434623566656139353039393334383162306661656130"
    "613932613764363162383931623938346432363865393035396564313136373561"
    "663836366131623737333165633039316635356132393164326439356563323239"
    "343834323933393834316661303163343032336634353163353237353330643637"
    "626230653737653661366538386466363266616234303032343539326565356132"
    "346137316230353732366638373637383562633132623865623433306164636638"
    "663165613938626663343132316566313865653131363739383366646436333464"
    "383739383131636633643233643030653130393738336365636137336131666164"
    "613636376366643931313533616663303463323865373962346433643636363761"
    "323761306130366664383565373134656630356234373836633838613139386333"
    "353863386366656332306462356631646231323838653938643366386637303062"
    "656538373664303561633662363339393938656363393931356333663466393434"
    "643834343130373364373734323636663336383732343039313936646236666161"
    "363362646333623730333339333330323862376133633262363236353731383930"
    "366362623030323231666333376537613062623032653534376533373736653236"
    "343938383336333964393964303462653965346331366535336366343533616166"
    "333664316664313736656335393338633836333634626261376230623136613934"
    "643732313439636236376134613038326333616136343931313161373137316136"
    "336365376262663530333534613533383966303939396332663762646235373838"
    "343465366332393238646463326164323365363763656533376366643331303434"
    "663564313639336535613965376538343934633136346464313735613863343138"
    "373132393564366566356532343462376163353830396132643039376635366663"
    "386538353336663064326362333838383237383564346530373535653866663533"
    "653039393466643336313264306462333133373633356330303230656163333765"
    "646338636433333163373863633062323839663832343935656162653031616637"
    "356233383163356662633831333034633535633862653435323130366336343932"
    "323730316536643533323839636531613635383466376462373231616130396566"
    "623333316237333436386531373632313336336430646235363836393561616436"
    "653134663339386330376361326137633536363565306230636137306566343963"
    "626438333361396663323230303837333531633739636166353336333836306434"
    "663861343034373165393435383962336263393434323639633865"
    "0d0a"
)

SAMANTHA_PLAINTEXT_START = "Final entry: I have run out of pages"
SAMANTHA_PLAINTEXT_CONTAINS = (
    "Monty says he is not dead but has just evolved into a new form"
)


def test_double_hex_blowfish_compat(cache):
    """hex > reverse > hex > blowfish-compat-cfb > b64."""
    key = b"Zombies"

    # Step 1: outer hex decode
    outer_hex = DOUBLE_HEX_CT.replace(" ", "").replace("\n", "")
    raw = bytes.fromhex(outer_hex)
    inner_text = raw.decode("ascii").rstrip("\r\n")

    # Step 2: reverse (pad leading "0" for odd length)
    if len(inner_text) % 2 != 0:
        inner_text = "0" + inner_text
    rev = inner_text[::-1]

    # Step 3: inner hex decode
    hex_bytes = bytes.fromhex(rev)

    # Step 4: blowfish-compat-cfb (IV = "0" * 8)
    s4 = mcrypt_decrypt(
        "blowfish-compat", "cfb", key, b"0" * 8, hex_bytes, handle_cache=cache
    )
    assert s4 is not None
    s4 = s4[: len(hex_bytes)]

    # Find end of b64 content (stop at first non-b64 byte)
    b64_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    end = 0
    for end in range(len(s4)):
        if s4[end] not in b64_chars:
            break
    b64_portion = s4[:end]
    # Pad to multiple of 4
    pad = (4 - len(b64_portion) % 4) % 4
    b64_padded = b64_portion + b"=" * pad

    # Step 5: base64 decode
    result = base64.b64decode(b64_padded)
    text = _strip_mcrypt_output(result).decode("utf-8")

    assert text.startswith(SAMANTHA_PLAINTEXT_START)
    assert SAMANTHA_PLAINTEXT_CONTAINS in text
