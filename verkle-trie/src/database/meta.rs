#![allow(clippy::identity_op)]
#![allow(clippy::large_enum_variant)]
use banderwagon::trait_defs::*;
use banderwagon::{Element, Fr};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StemMeta {
    pub c_1: Element,
    pub hash_c1: Fr,

    pub c_2: Element,
    pub hash_c2: Fr,

    pub stem_commitment: Element,
    pub hash_stem_commitment: Fr,
}
impl std::fmt::Debug for StemMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StemMeta")
            .field(
                "c_1",
                &hex::encode(compress_point_to_array(&self.c_1).unwrap()),
            )
            .field(
                "c_2",
                &hex::encode(compress_point_to_array(&self.c_2).unwrap()),
            )
            .field(
                "hash_c1",
                &hex::encode(scalar_to_array(&self.hash_c1).unwrap()),
            )
            .field(
                "hash_c2",
                &hex::encode(scalar_to_array(&self.hash_c2).unwrap()),
            )
            .field(
                "stem commitment",
                &hex::encode(compress_point_to_array(&self.stem_commitment).unwrap()),
            )
            .field(
                "hash_stem_commitment",
                &hex::encode(scalar_to_array(&self.hash_stem_commitment).unwrap()),
            )
            .finish()
    }
}

fn point_to_array(p: &Element) -> Result<[u8; 64], SerializationError> {
    let mut bytes = [0u8; 64];
    p.serialize_uncompressed(&mut bytes[..])?;

    Ok(bytes)
}
fn compress_point_to_array(p: &Element) -> Result<[u8; 32], SerializationError> {
    let mut bytes = [0u8; 32];
    p.serialize_compressed(&mut bytes[..])?;

    Ok(bytes)
}
fn scalar_to_array(scalar: &Fr) -> Result<[u8; 32], SerializationError> {
    let mut bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut bytes[..])?;

    Ok(bytes)
}

impl FromBytes<Vec<u8>> for StemMeta {
    // panic if we cannot deserialize, do not call this method if you are unsure if the data is
    // not structured properly. We can guarantee this in verkle trie.
    fn from_bytes(bytes: Vec<u8>) -> Result<StemMeta, SerializationError> {
        let len = bytes.len();
        // 3 points * 64 bytes + 3 scalars * 32 bytes = 288 bytes total
        if len != 64 * 3 + 32 * 3 {
            return Err(SerializationError::InvalidData);
        }

        let point_bytes = &bytes[0..64 * 3];
        #[allow(clippy::erasing_op)]
        let c_1 = Element::deserialize_uncompressed(&point_bytes[0 * 64..1 * 64])?;
        let c_2 = Element::deserialize_uncompressed(&point_bytes[1 * 64..2 * 64])?;
        let stem_commitment = Element::deserialize_uncompressed(&point_bytes[2 * 64..3 * 64])?;

        let scalar_bytes = &bytes[64 * 3..];
        #[allow(clippy::erasing_op)]
        let hash_c1 = Fr::deserialize_uncompressed(&scalar_bytes[0 * 32..1 * 32])?;
        let hash_c2 = Fr::deserialize_uncompressed(&scalar_bytes[1 * 32..2 * 32])?;
        let hash_stem_commitment = Fr::deserialize_uncompressed(&scalar_bytes[2 * 32..3 * 32])?;

        Ok(StemMeta {
            c_1,
            hash_c1,
            c_2,
            hash_c2,
            stem_commitment,
            hash_stem_commitment,
        })
    }
}

impl ToBytes<Vec<u8>> for StemMeta {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::with_capacity(3 * (64 + 32));

        bytes.extend(point_to_array(&self.c_1)?);
        bytes.extend(point_to_array(&self.c_2)?);
        bytes.extend(point_to_array(&self.stem_commitment)?);

        bytes.extend(scalar_to_array(&self.hash_c1)?);
        bytes.extend(scalar_to_array(&self.hash_c2)?);
        bytes.extend(scalar_to_array(&self.hash_stem_commitment)?);

        Ok(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BranchMeta {
    pub commitment: Element,
    pub hash_commitment: Fr,
}
impl std::fmt::Debug for BranchMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchMeta")
            .field(
                "commitment",
                &hex::encode(compress_point_to_array(&self.commitment).unwrap()),
            )
            .field(
                "hash_commitment",
                &hex::encode(scalar_to_array(&self.hash_commitment).unwrap()),
            )
            .finish()
    }
}
impl BranchMeta {
    pub fn zero() -> BranchMeta {
        use banderwagon::trait_defs::*;
        BranchMeta {
            commitment: Element::zero(),
            hash_commitment: Fr::zero(),
        }
    }
}

use crate::from_to_bytes::{FromBytes, ToBytes};

impl FromBytes<Vec<u8>> for BranchMeta {
    fn from_bytes(bytes: Vec<u8>) -> Result<BranchMeta, SerializationError> {
        let len = bytes.len();
        if len != 32 + 64 {
            return Err(SerializationError::InvalidData);
        }

        let point_bytes = &bytes[0..64];
        let scalar_bytes = &bytes[64..64 + 32];

        let commitment = Element::deserialize_uncompressed(point_bytes)?;
        let hash_commitment = Fr::deserialize_uncompressed(scalar_bytes)?;

        Ok(BranchMeta {
            commitment,
            hash_commitment,
        })
    }
}

impl ToBytes<Vec<u8>> for BranchMeta {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::with_capacity(64 + 32);

        bytes.extend(point_to_array(&self.commitment)?);
        bytes.extend(scalar_to_array(&self.hash_commitment)?);

        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Meta {
    Stem(StemMeta),
    Branch(BranchMeta),
}
impl Meta {
    pub fn into_stem(self) -> StemMeta {
        match self {
            Meta::Stem(sm) => sm,
            Meta::Branch(_) => panic!("item is a branch and not a stem"),
        }
    }
    pub fn is_stem_meta(&self) -> bool {
        match self {
            Meta::Stem(_) => true,
            Meta::Branch(_) => false,
        }
    }
    pub fn is_branch_meta(&self) -> bool {
        match self {
            Meta::Stem(_) => false,
            Meta::Branch(_) => true,
        }
    }
    pub fn into_branch(self) -> BranchMeta {
        match self {
            Meta::Stem(_) => panic!("item is a stem and not a branch"),
            Meta::Branch(bm) => bm,
        }
    }
}
impl From<StemMeta> for Meta {
    fn from(sm: StemMeta) -> Self {
        Meta::Stem(sm)
    }
}
impl From<BranchMeta> for Meta {
    fn from(bm: BranchMeta) -> Self {
        Meta::Branch(bm)
    }
}
#[derive(Debug, Clone, Copy)]
pub enum BranchChild {
    Stem([u8; 31]),
    Branch(BranchMeta),
}

// Type discriminator bytes for BranchChild serialization
const BRANCH_CHILD_STEM_TAG: u8 = 0x00;
const BRANCH_CHILD_BRANCH_TAG: u8 = 0x01;

impl ToBytes<Vec<u8>> for BranchChild {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        match self {
            BranchChild::Stem(stem_id) => {
                let mut bytes = Vec::with_capacity(1 + 31);
                bytes.push(BRANCH_CHILD_STEM_TAG);
                bytes.extend_from_slice(stem_id);
                Ok(bytes)
            }
            BranchChild::Branch(bm) => {
                let mut bytes = Vec::with_capacity(1 + 96);
                bytes.push(BRANCH_CHILD_BRANCH_TAG);
                bytes.extend(bm.to_bytes()?);
                Ok(bytes)
            }
        }
    }
}

impl FromBytes<Vec<u8>> for BranchChild {
    fn from_bytes(bytes: Vec<u8>) -> Result<BranchChild, SerializationError> {
        if bytes.is_empty() {
            return Err(SerializationError::InvalidData);
        }

        let tag = bytes[0];
        let data = &bytes[1..];

        match tag {
            BRANCH_CHILD_STEM_TAG => {
                if data.len() != 31 {
                    return Err(SerializationError::InvalidData);
                }
                Ok(BranchChild::Stem(data.try_into().unwrap()))
            }
            BRANCH_CHILD_BRANCH_TAG => {
                let branch_meta = BranchMeta::from_bytes(data.to_vec())?;
                Ok(BranchChild::Branch(branch_meta))
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl BranchChild {
    pub fn is_branch(&self) -> bool {
        match self {
            BranchChild::Stem(_) => false,
            BranchChild::Branch(_) => true,
        }
    }
    pub fn branch(&self) -> Option<BranchMeta> {
        match self {
            BranchChild::Stem(_) => None,
            BranchChild::Branch(bm) => Some(*bm),
        }
    }
    pub fn stem(&self) -> Option<[u8; 31]> {
        match self {
            BranchChild::Stem(stem_id) => Some(*stem_id),
            BranchChild::Branch(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_meta_from_bytes_validates_length() {
        // Empty bytes should fail
        let result = BranchMeta::from_bytes(vec![]);
        assert!(result.is_err());

        // Wrong length (too short) should fail
        let result = BranchMeta::from_bytes(vec![0u8; 50]);
        assert!(result.is_err());

        // Wrong length (too long) should fail
        let result = BranchMeta::from_bytes(vec![0u8; 100]);
        assert!(result.is_err());

        // Exactly 31 bytes (stem size) should fail
        let result = BranchMeta::from_bytes(vec![0u8; 31]);
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_meta_serialization_roundtrip() {
        let meta = BranchMeta::zero();
        let bytes = meta.to_bytes().unwrap();

        // Verify correct size: 64 (point) + 32 (scalar) = 96 bytes
        assert_eq!(bytes.len(), 96);

        let recovered = BranchMeta::from_bytes(bytes).unwrap();
        assert_eq!(meta, recovered);
    }

    #[test]
    fn test_branch_child_stem_serialization_roundtrip() {
        let stem_id: [u8; 31] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31,
        ];
        let branch_child = BranchChild::Stem(stem_id);

        let bytes = branch_child.to_bytes().unwrap();

        // Should be 1 byte tag + 31 bytes stem_id = 32 bytes
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], BRANCH_CHILD_STEM_TAG);

        let recovered = BranchChild::from_bytes(bytes).unwrap();
        match recovered {
            BranchChild::Stem(recovered_stem) => assert_eq!(recovered_stem, stem_id),
            BranchChild::Branch(_) => panic!("Expected Stem variant"),
        }
    }

    #[test]
    fn test_branch_child_branch_serialization_roundtrip() {
        let meta = BranchMeta::zero();
        let branch_child = BranchChild::Branch(meta);

        let bytes = branch_child.to_bytes().unwrap();

        // Should be 1 byte tag + 96 bytes BranchMeta = 97 bytes
        assert_eq!(bytes.len(), 97);
        assert_eq!(bytes[0], BRANCH_CHILD_BRANCH_TAG);

        let recovered = BranchChild::from_bytes(bytes).unwrap();
        match recovered {
            BranchChild::Branch(recovered_meta) => assert_eq!(recovered_meta, meta),
            BranchChild::Stem(_) => panic!("Expected Branch variant"),
        }
    }

    #[test]
    fn test_branch_child_from_bytes_rejects_invalid_data() {
        // Empty bytes should fail
        let result = BranchChild::from_bytes(vec![]);
        assert!(result.is_err());

        // Invalid tag should fail
        let result = BranchChild::from_bytes(vec![0xFF, 1, 2, 3]);
        assert!(result.is_err());

        // Stem tag with wrong data length should fail
        let mut bad_stem = vec![BRANCH_CHILD_STEM_TAG];
        bad_stem.extend_from_slice(&[0u8; 30]); // Only 30 bytes, not 31
        let result = BranchChild::from_bytes(bad_stem);
        assert!(result.is_err());

        // Branch tag with wrong data length should fail
        let mut bad_branch = vec![BRANCH_CHILD_BRANCH_TAG];
        bad_branch.extend_from_slice(&[0u8; 50]); // Only 50 bytes, not 96
        let result = BranchChild::from_bytes(bad_branch);
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_child_type_discriminator_prevents_confusion() {
        // Create a stem with 31 bytes
        let stem_id: [u8; 31] = [0xAB; 31];
        let stem_child = BranchChild::Stem(stem_id);
        let stem_bytes = stem_child.to_bytes().unwrap();

        // Create a branch
        let branch_child = BranchChild::Branch(BranchMeta::zero());
        let branch_bytes = branch_child.to_bytes().unwrap();

        // Verify they have different tags
        assert_ne!(stem_bytes[0], branch_bytes[0]);

        // Verify deserialization produces correct types
        let recovered_stem = BranchChild::from_bytes(stem_bytes).unwrap();
        assert!(recovered_stem.stem().is_some());
        assert!(recovered_stem.branch().is_none());

        let recovered_branch = BranchChild::from_bytes(branch_bytes).unwrap();
        assert!(recovered_branch.branch().is_some());
        assert!(recovered_branch.stem().is_none());
    }

    #[test]
    fn test_stem_meta_serialization_roundtrip() {
        use banderwagon::trait_defs::*;

        let meta = StemMeta {
            c_1: Element::zero(),
            hash_c1: Fr::zero(),
            c_2: Element::zero(),
            hash_c2: Fr::zero(),
            stem_commitment: Element::zero(),
            hash_stem_commitment: Fr::zero(),
        };

        let bytes = meta.to_bytes().unwrap();

        // Verify correct size: 3 * 64 (points) + 3 * 32 (scalars) = 288 bytes
        assert_eq!(bytes.len(), 288);

        let recovered = StemMeta::from_bytes(bytes).unwrap();
        assert_eq!(meta, recovered);
    }

    #[test]
    fn test_stem_meta_with_real_point() {
        use banderwagon::trait_defs::*;
        use banderwagon::Fr;

        // Create a non-trivial point by multiplying generator by a scalar
        let generator = Element::prime_subgroup_generator();
        let scalar = Fr::from(12345u64);
        let point = generator * scalar;

        let meta = StemMeta {
            c_1: point,
            hash_c1: scalar,
            c_2: Element::zero(),
            hash_c2: Fr::zero(),
            stem_commitment: Element::zero(),
            hash_stem_commitment: Fr::zero(),
        };

        let bytes = meta.to_bytes().unwrap();
        println!("First 64 bytes (c_1): {:?}", &bytes[0..64]);

        let recovered = StemMeta::from_bytes(bytes).unwrap();
        assert_eq!(meta.c_1, recovered.c_1);
        assert_eq!(meta.hash_c1, recovered.hash_c1);
    }

    #[test]
    fn test_element_uncompressed_roundtrip() {
        use banderwagon::trait_defs::*;
        use banderwagon::Fr;

        // Create a non-trivial point
        let generator = Element::prime_subgroup_generator();
        let scalar = Fr::from(12345u64);
        let point = generator * scalar;

        // Serialize uncompressed
        let mut bytes = [0u8; 64];
        point.serialize_uncompressed(&mut bytes[..]).unwrap();
        println!("Serialized bytes: {:?}", &bytes[..]);

        // Deserialize uncompressed
        let recovered = Element::deserialize_uncompressed(&bytes[..]).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_stem_meta_from_bytes_validates_length() {
        // Empty bytes should fail
        let result = StemMeta::from_bytes(vec![]);
        assert!(result.is_err());

        // Wrong length should fail
        let result = StemMeta::from_bytes(vec![0u8; 100]);
        assert!(result.is_err());

        // Wrong length (close but not exact) should fail
        let result = StemMeta::from_bytes(vec![0u8; 287]);
        assert!(result.is_err());
    }
}
