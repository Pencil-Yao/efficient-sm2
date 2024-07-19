THE SOFTWARE IS PROVIDED "AS IS" AND YAO PENGFEI AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL YAO PENGFEI OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*efficient-sm2*
=====

this repo is pure rust to achieve sm2 signing/verification algorithm, and it's performance better than other sm2
library. What's more, you could change the struct `CURVE_PARAMS` to other Elliptic Curve's params and enjoy greate
performance.

## usage

``` rust
use rand::RngCore;

fn main() {
    let test_word = b"hello world";

    let mut private_key = [0; 32];
    rand::thread_rng().fill_bytes(&mut private_key);

    let key_pair = efficient_sm2::KeyPair::new(&private_key).unwrap();

    // signing in sm2
    let sig = key_pair.sign(test_word).unwrap();

    // verification sm2 signature
    sig.verify(&key_pair.public_key(), test_word).unwrap();
}
```

## bench

``` shell
 cargo +nightly bench --workspace --features internal_benches
```

### result

```
test ec::signing::sign_bench::es_sign_bench                ... bench:      52,532 ns/iter (+/- 730)
test ec::signing::sign_bench::es_sign_without_sm3_bench    ... bench:      27,474 ns/iter (+/- 336)
test ec::signing::sign_bench::es_verify_bench              ... bench:     117,975 ns/iter (+/- 992)
test ec::signing::sign_bench::libsm_sign_bench             ... bench:     105,183 ns/iter (+/- 1,347)
test ec::signing::sign_bench::libsm_sign_without_sm3_bench ... bench:      82,389 ns/iter (+/- 1,235)
test ec::signing::sign_bench::libsm_verify_bench           ... bench:     562,687 ns/iter (+/- 43,833)
test sm2p256::sm2_bench::add_mod_bench                     ... bench:           1 ns/iter (+/- 0)
test sm2p256::sm2_bench::base_point_mul_bench              ... bench:       8,387 ns/iter (+/- 70)
test sm2p256::sm2_bench::big_number_bench                  ... bench:         177 ns/iter (+/- 0)
test sm2p256::sm2_bench::libsm_mul_mod_bench               ... bench:          99 ns/iter (+/- 7)
test sm2p256::sm2_bench::mont_pro_bench                    ... bench:          29 ns/iter (+/- 0)
test sm2p256::sm2_bench::point_add_bench                   ... bench:         269 ns/iter (+/- 3)
test sm2p256::sm2_bench::point_double_bench                ... bench:         267 ns/iter (+/- 4)
test sm2p256::sm2_bench::point_mul_bench                   ... bench:      90,584 ns/iter (+/- 2,239)
test sm2p256::sm2_bench::shl_bak_bench                     ... bench:          43 ns/iter (+/- 0)
test sm2p256::sm2_bench::shl_bench                         ... bench:           5 ns/iter (+/- 0)
test sm2p256::sm2_bench::sub_mod_bench                     ... bench:           2 ns/iter (+/- 0)
```

ps. bench environment:

* `cpu`: `amd r7 4800-h`
* `memory`: `32g`
* `os`: `ubuntu 20.04`
