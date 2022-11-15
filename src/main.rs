use std::env;

#[derive(Default, Debug)]
pub struct Decoder {
    random_seed: u32,
}

impl Decoder {
    fn hexstr2bytearray(string: &str) -> Option<Vec<u32>> {
        let mut result = Vec::new();
        let len = string.len();

        if len == 0 || (len & 1) != 0 {
            return None;
        }

        for i in (0..len).step_by(2) {
            result.push(u32::from_str_radix(&string[i..i + 2], 16).unwrap());
        }

        Some(result)
    }

    // initialize random generator with specified seed
    pub fn srand(&mut self, seed: u32) {
        self.random_seed = seed;
    }

    // generate pseudo-random number from the specified seed
    pub fn rand_max(&mut self, n_max: usize) -> u8 {
        // cut numbers to 32 bit values (important)
        self.random_seed = ((((self.random_seed as u64) * 0x8088405) & 0xFFFFFFFF) + 1) as u32;

        ((self.random_seed as u64 * n_max as u64) >> 32) as u8
    }

    // rotate bits left
    pub fn rol8(var: u32, counter: u8) -> u8 {
        let var = var as u64;
        ((var << counter) | (var >> (8 - counter))) as u8
    }

    // decrypt Total Commander FTP password
    pub fn decrypt_password(&mut self, password: &str) -> Option<String> {
        // convert hex string to array of integers
        // if the conversion failed - exit
        let password_hex_u32 = Self::hexstr2bytearray(password)?;

        // number of converted bytes
        let mut password_length = password_hex_u32.len();

        // length includes checksum at the end
        if password_length <= 4 {
            return None;
        }

        // minus checksum
        password_length -= 4;

        self.srand(849521);

        let mut password_hex = Vec::new();
        for hex in password_hex_u32.into_iter().take(password_length) {
            password_hex.push(Self::rol8(hex, self.rand_max(8)));
        }

        self.srand(12345);

        for _ in 0..256 {
            let x = self.rand_max(password_length) as usize;
            let y = self.rand_max(password_length) as usize;

            password_hex.swap(x, y);
        }

        self.srand(42340);

        for hex in password_hex.iter_mut() {
            *hex ^= self.rand_max(256);
        }

        self.srand(54321);

        for hex in password_hex.iter_mut() {
            *hex = (*hex).wrapping_sub(self.rand_max(256));
        }

        // build final password
        let mut decoded_password = String::new();

        for hex in password_hex {
            decoded_password.push(char::from(hex));
        }

        Some(decoded_password)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut decoder = Decoder::default();
    let pass = decoder
        .decrypt_password(
            &args
                .get(1)
                .expect("Please pass password HASH as first argument"),
        )
        .unwrap();
    println!("password = {pass}");
}
