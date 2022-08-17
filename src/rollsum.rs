use std::num::Wrapping;

const CHAR_OFFSET: Wrapping<u16> = Wrapping(31);

#[derive(Debug, Default, Copy, Clone)]
pub struct Window {
    count: Wrapping<u16>,

    s1: Wrapping<u16>,

    s2: Wrapping<u16>,
}

impl Window {
    pub fn new() -> Window {
        Window::default()
    }
}

pub trait Rollsum {
    fn digest(&self) -> u32;

    fn roll_in(&mut self, c_in: u8);

    fn roll_out(&mut self, c_out: u8);

    fn rotate(&mut self, c_out: u8, c_in: u8);

    fn update(&mut self, buf: &[u8]);
}

impl Rollsum for Window {
    fn digest(&self) -> u32 {
        (self.s2.0 as u32) << 16 | (self.s1.0 as u32)
    }

    fn roll_in(&mut self, c_in: u8) {
        self.s1 += CHAR_OFFSET + Wrapping(c_in as u16);
        self.s2 += self.s1;
        self.count += Wrapping(1);
    }

    fn roll_out(&mut self, c_out: u8) {
        let c_out = Wrapping(c_out as u16);
        self.s1 -= c_out + CHAR_OFFSET;
        self.s2 -= self.count * (c_out + CHAR_OFFSET);
        self.count -= Wrapping(1);
    }

    fn rotate(&mut self, c_out: u8, c_in: u8) {
        let c_in = Wrapping(c_in as u16);
        let c_out = Wrapping(c_out as u16);
        self.s1 += c_in - c_out;
        self.s2 += self.s1 - (self.count * (c_out + CHAR_OFFSET));
    }

    fn update(&mut self, buf: &[u8]) {
        let mut s1 = self.s1;
        let mut s2 = self.s2;
        for c in buf {
            s1 += Wrapping(*c as u16);
            s2 += s1;
        }
        let len = buf.len() as u32;
        let ll = Wrapping(buf.len() as u16);
        let trilen = Wrapping(((len * (len + 1)) / 2) as u16);

        s1 += ll * CHAR_OFFSET;
        s2 += trilen * CHAR_OFFSET;

        self.count += ll;
        self.s1 = s1;
        self.s2 = s2;
    }
}

#[cfg(test)]
mod test {
    use super::{Rollsum, Window};

    #[test]
    pub fn default_value() {
        let rs = Window::new();
        assert_eq!(rs.count.0, 0);
        assert_eq!(rs.s1.0, 0);
        assert_eq!(rs.s2.0, 0);
        assert_eq!(rs.digest(), 0u32);
    }

    #[test]
    pub fn rollsum() {
        let mut rs = Window::new();
        rs.roll_in(0u8);
        assert_eq!(rs.count.0, 1);
        assert_eq!(rs.digest(), 0x001f001f);

        rs.roll_in(1u8);
        rs.roll_in(2u8);
        rs.roll_in(3u8);
        assert_eq!(rs.count.0, 4);
        assert_eq!(rs.digest(), 0x01400082);

        rs.rotate(0, 4);
        assert_eq!(rs.count.0, 4);
        assert_eq!(rs.digest(), 0x014a0086);

        rs.rotate(1, 5);
        rs.rotate(2, 6);
        rs.rotate(3, 7);
        assert_eq!(rs.count.0, 4);
        assert_eq!(rs.digest(), 0x01680092);

        rs.roll_out(4);
        assert_eq!(rs.count.0, 3);
        assert_eq!(rs.digest(), 0x00dc006f);

        rs.roll_out(5);
        rs.roll_out(6);
        rs.roll_out(7);
        assert_eq!(rs.count.0, 0);
        assert_eq!(rs.digest(), 0);
    }

    #[test]
    pub fn update() {
        let mut rs = Window::new();
        let mut buf = [0u8; 256];
        for i in 0..buf.len() {
            buf[i] = i as u8;
        }
        rs.update(&buf);
        assert_eq!(rs.digest(), 0x3a009e80);
    }
}
