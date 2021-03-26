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
library. What's more, you could change the struct `CURVE_PARAMS` to other Elliptic Curve's params and enjot greate
performance. 

## usage

``` rust
use rand::Rng;

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
test ec::signing::sign_bench::es_sign_bench      ... bench:      59,064 ns/iter (+/- 1,151)
test ec::signing::sign_bench::es_verify_bench    ... bench:     156,189 ns/iter (+/- 22,855)
test ec::signing::sign_bench::libsm_sign_bench   ... bench:     208,987 ns/iter (+/- 7,795)
test ec::signing::sign_bench::libsm_verify_bench ... bench:     831,658 ns/iter (+/- 282,336)
test sm2p256::sm2_bench::add_mod_bench           ... bench:           9 ns/iter (+/- 0)
test sm2p256::sm2_bench::base_point_mul_bench    ... bench:      10,333 ns/iter (+/- 5,102)
test sm2p256::sm2_bench::big_number_bench        ... bench:         733 ns/iter (+/- 122)
test sm2p256::sm2_bench::libsm_mul_mod_bench     ... bench:          93 ns/iter (+/- 5)
test sm2p256::sm2_bench::mont_pro_bench          ... bench:          31 ns/iter (+/- 0)
test sm2p256::sm2_bench::point_add_bench         ... bench:         345 ns/iter (+/- 128)
test sm2p256::sm2_bench::point_double_bench      ... bench:         431 ns/iter (+/- 154)
test sm2p256::sm2_bench::point_mul_bench         ... bench:     110,865 ns/iter (+/- 565)
test sm2p256::sm2_bench::shl_bak_bench           ... bench:          52 ns/iter (+/- 0)
test sm2p256::sm2_bench::shl_bench               ... bench:          17 ns/iter (+/- 1)
test sm2p256::sm2_bench::sub_mod_bench           ... bench:          10 ns/iter (+/- 0)
```
ps. bench environment: 
* `cpu`: `amd r7 4800-h`
* `memory`: `32g`
* `os`: `ubuntu 20.04`
