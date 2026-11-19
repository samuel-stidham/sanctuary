//! The release of the Go original this build is held to.
//!
//! This file is the one place that release is named. A move to a new
//! release changes the tag and the commit here and nothing else. The
//! version line reads the tag. The `Makefile` reads both to build the
//! reference binary.

/// The tag of the Go release, as a literal so `concat!` can take it.
macro_rules! tag {
    () => {
        "v4.0.3"
    };
}

pub(crate) use tag;

/// The tag of the Go release.
pub const TAG: &str = tag!();

/// The commit that tag names.
pub const COMMIT: &str = "f0578032f476e848bc55b18334792db05c9167b9";

#[cfg(test)]
mod tests {
    use super::{COMMIT, TAG};

    // The Makefile reads both values out of this file by their shape.
    #[test]
    fn the_tag_and_the_commit_keep_the_shape_the_makefile_reads() {
        let numbers: Vec<&str> = TAG
            .strip_prefix('v')
            .expect("a v prefix")
            .split('.')
            .collect();

        assert_eq!(numbers.len(), 3);
        assert!(numbers.iter().all(|part| part.parse::<u32>().is_ok()));

        assert_eq!(COMMIT.len(), 40);
        assert!(COMMIT.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
