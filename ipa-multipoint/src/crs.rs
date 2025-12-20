use crate::{default_crs, ipa::slow_vartime_multiscalar_mul, lagrange_basis::LagrangeBasis};
use banderwagon::{try_reduce_to_element, Element};
use thiserror::Error;

/// Size of a single uncompressed point in bytes
pub const UNCOMPRESSED_POINT_SIZE: usize = 64;

#[derive(Debug, Error)]
pub enum CRSError {
    #[error("Invalid CRS byte length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Duplicate points detected in CRS at indices {0} and {1}")]
    DuplicatePoints(usize, usize),

    #[error("Failed to deserialize point at index {index}: {reason}")]
    PointDeserializationError { index: usize, reason: String },
}

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct CRS {
    pub n: usize,
    pub G: Vec<Element>,
    pub Q: Element,
}

impl Default for CRS {
    fn default() -> Self {
        CRS::from_hex(&default_crs::HEX_ENCODED_CRS)
    }
}

impl CRS {
    #[allow(non_snake_case)]
    pub fn new(n: usize, seed: &'static [u8]) -> CRS {
        // TODO generate the Q value from the seed also
        // TODO: this will also make assert_dedup work as expected
        // TODO: since we should take in `Q` too
        let G: Vec<_> = generate_random_elements(n, seed).into_iter().collect();
        let Q = Element::prime_subgroup_generator();

        CRS::assert_dedup(&G);

        CRS { n, G, Q }
    }

    /// Returns the maximum number of elements that can be committed to
    pub fn max_number_of_elements(&self) -> usize {
        self.n
    }

    #[allow(non_snake_case)]
    // The last element is implied to be `Q`
    pub fn from_bytes(bytes: &[[u8; 64]]) -> Result<CRS, CRSError> {
        let (q_bytes, g_vec_bytes) = bytes
            .split_last()
            .ok_or_else(|| CRSError::InvalidLength {
                expected: 1,
                actual: 0,
            })?;

        let Q = Element::try_from_bytes_uncompressed(*q_bytes).map_err(|e| {
            CRSError::PointDeserializationError {
                index: g_vec_bytes.len(),
                reason: e.to_string(),
            }
        })?;

        let mut G = Vec::with_capacity(g_vec_bytes.len());
        for (index, bytes) in g_vec_bytes.iter().enumerate() {
            let point = Element::try_from_bytes_uncompressed(*bytes).map_err(|e| {
                CRSError::PointDeserializationError {
                    index,
                    reason: e.to_string(),
                }
            })?;
            G.push(point);
        }

        // Check for duplicates
        Self::validate_no_duplicates(&G)?;

        let n = G.len();
        Ok(CRS { G, Q, n })
    }

    /// Deserialize CRS from bytes, panicking on error
    ///
    /// # Panics
    /// Panics if bytes are invalid. Prefer `from_bytes()` which returns Result.
    #[deprecated(since = "1.0.0", note = "Use from_bytes() which returns Result")]
    pub fn from_bytes_unchecked(bytes: &[[u8; 64]]) -> Self {
        Self::from_bytes(bytes).expect("Failed to deserialize CRS")
    }
    pub fn from_hex(hex_encoded_crs: &[&str]) -> CRS {
        let bytes: Vec<[u8; 64]> = hex_encoded_crs
            .iter()
            .map(|hex| hex::decode(hex).unwrap())
            .map(|byte_vector| byte_vector.try_into().unwrap())
            .collect();
        CRS::from_bytes(&bytes).expect("Failed to deserialize CRS from hex")
    }

    pub fn to_bytes(&self) -> Vec<[u8; 64]> {
        let mut bytes = Vec::with_capacity(self.n + 1);
        for point in &self.G {
            bytes.push(point.to_bytes_uncompressed());
        }
        bytes.push(self.Q.to_bytes_uncompressed());
        bytes
    }

    pub fn to_hex(&self) -> Vec<String> {
        self.to_bytes().iter().map(hex::encode).collect()
    }

    /// Check that no two points in the CRS are identical
    fn validate_no_duplicates(points: &[Element]) -> Result<(), CRSError> {
        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                if points[i] == points[j] {
                    return Err(CRSError::DuplicatePoints(i, j));
                }
            }
        }
        Ok(())
    }

    // Asserts that not of the points generated are the same
    fn assert_dedup(points: &[Element]) {
        use std::collections::HashSet;
        let mut map = HashSet::new();
        for point in points {
            let value_is_new = map.insert(point.to_bytes());
            assert!(value_is_new, "crs has duplicated points")
        }
    }
    pub fn commit_lagrange_poly(&self, polynomial: &LagrangeBasis) -> Element {
        slow_vartime_multiscalar_mul(polynomial.values().iter(), self.G.iter())
    }
}

impl std::ops::Index<usize> for CRS {
    type Output = Element;

    fn index(&self, index: usize) -> &Self::Output {
        &self.G[index]
    }
}

fn generate_random_elements(num_required_points: usize, seed: &'static [u8]) -> Vec<Element> {
    use sha2::{Digest, Sha256};

    let _choose_largest = false;

    // Hash the seed + i to get a possible x value
    let hash_to_x = |index: u64| -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(index.to_be_bytes());
        let bytes: Vec<u8> = hasher.finalize().to_vec();
        bytes
    };

    (0u64..)
        .map(hash_to_x)
        .filter_map(|hash_bytes| try_reduce_to_element(&hash_bytes))
        .take(num_required_points)
        .collect()
}

#[test]
fn crs_consistency() {
    // TODO: update hackmd as we are now using banderwagon and the point finding strategy
    // TODO is a bit different
    // See: https://hackmd.io/1RcGSMQgT4uREaq1CCx_cg#Methodology

    use sha2::{Digest, Sha256};

    let points = generate_random_elements(256, b"eth_verkle_oct_2021");

    let bytes = points[0].to_bytes();
    assert_eq!(
        hex::encode(bytes),
        "01587ad1336675eb912550ec2a28eb8923b824b490dd2ba82e48f14590a298a0",
        "the first point is incorrect"
    );
    let bytes = points[255].to_bytes();
    assert_eq!(
        hex::encode(bytes),
        "3de2be346b539395b0c0de56a5ccca54a317f1b5c80107b0802af9a62276a4d8",
        "the 256th (last) point is incorrect"
    );

    let mut hasher = Sha256::new();
    for point in &points {
        let bytes = point.to_bytes();
        hasher.update(bytes);
    }
    let bytes = hasher.finalize().to_vec();
    assert_eq!(
        hex::encode(bytes),
        "1fcaea10bf24f750200e06fa473c76ff0468007291fa548e2d99f09ba9256fdb",
        "unexpected point encountered"
    );
}

#[test]
fn load_from_bytes_to_bytes() {
    let crs = CRS::new(256, b"eth_verkle_oct_2021");
    let bytes = crs.to_bytes();
    let crs2 = CRS::from_bytes(&bytes).expect("should deserialize");
    let bytes2 = crs2.to_bytes();

    let hex: Vec<_> = bytes.iter().map(hex::encode).collect();
    dbg!(hex);

    assert_eq!(bytes, bytes2, "bytes should be the same");
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    /// Test: Valid CRS bytes deserialize successfully
    #[test]
    fn test_from_bytes_valid() {
        let crs = CRS::new(256, b"test_seed");
        let bytes = crs.to_bytes();

        let restored = CRS::from_bytes(&bytes);
        assert!(restored.is_ok());
        assert_eq!(restored.unwrap().G.len(), 256);
    }

    /// Test: Empty bytes returns InvalidLength error
    #[test]
    fn test_from_bytes_empty() {
        let result = CRS::from_bytes(&[]);
        assert!(matches!(
            result,
            Err(CRSError::InvalidLength { expected: 1, actual: 0 })
        ));
    }

    /// Test: Corrupted point returns PointDeserializationError
    #[test]
    fn test_from_bytes_corrupted_point() {
        // Create array of invalid point data (all 0xFF bytes)
        let corrupted_bytes: Vec<[u8; 64]> = vec![[0xFF; 64]; 257]; // 256 G points + 1 Q point

        let result = CRS::from_bytes(&corrupted_bytes);
        // The last point is Q, so it should fail at index 256
        assert!(matches!(
            result,
            Err(CRSError::PointDeserializationError { index: 256, .. })
        ));
    }

    /// Test: Duplicate points returns DuplicatePoints error
    #[test]
    fn test_from_bytes_duplicate_points() {
        let crs = CRS::new(256, b"test_seed");
        let mut bytes = crs.to_bytes();

        // Copy first point to second position
        bytes[1] = bytes[0];

        let result = CRS::from_bytes(&bytes);
        assert!(matches!(result, Err(CRSError::DuplicatePoints(0, 1))));
    }
}
