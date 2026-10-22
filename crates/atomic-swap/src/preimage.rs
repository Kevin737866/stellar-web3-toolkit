use crate::error::{AtomicSwapError, Result};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use soroban_sdk::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Preimage {
    pub data: Vec<u8>,
    pub hash: Vec<u8>,
    pub created_at: u64,
}

impl Preimage {
    /// Generate a new random preimage with its SHA-256 hash
    pub fn generate(size: usize) -> Result<Self> {
        if size == 0 || size > 1024 {
            return Err(AtomicSwapError::PreimageGenerationError(
                "Invalid preimage size".to_string(),
            ));
        }

        let mut rng = thread_rng();
        let mut data = vec![0u8; size];
        rng.fill(&mut data[..]);

        let hash = Self::compute_hash(&data)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AtomicSwapError::PreimageGenerationError(e.to_string()))?
            .as_secs();

        Ok(Self {
            data,
            hash,
            created_at,
        })
    }

    /// Generate a preimage from a specific seed (for testing/deterministic cases)
    pub fn from_seed(seed: &str) -> Result<Self> {
        let data = seed.as_bytes().to_vec();
        let hash = Self::compute_hash(&data)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AtomicSwapError::PreimageGenerationError(e.to_string()))?
            .as_secs();

        Ok(Self {
            data,
            hash,
            created_at,
        })
    }

    /// Create a preimage from existing data
    pub fn from_data(data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return Err(AtomicSwapError::PreimageGenerationError(
                "Empty preimage data".to_string(),
            ));
        }

        let hash = Self::compute_hash(&data)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AtomicSwapError::PreimageGenerationError(e.to_string()))?
            .as_secs();

        Ok(Self {
            data,
            hash,
            created_at,
        })
    }

    /// Compute SHA-256 hash of the preimage data
    pub fn compute_hash(data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Verify that the provided hash matches the preimage
    pub fn verify_hash(&self, hash: &[u8]) -> bool {
        self.hash == hash
    }

    /// Convert to Soroban Bytes
    pub fn to_soroban_bytes(&self, env: &soroban_sdk::Env) -> Bytes {
        Bytes::from_slice(env, &self.data)
    }

    /// Convert hash to fixed 32-byte array
    pub fn hash_as_fixed(&self) -> Result<[u8; 32]> {
        if self.hash.len() != 32 {
            return Err(AtomicSwapError::HashComputationError(
                "Invalid hash length".to_string(),
            ));
        }

        let mut fixed_hash = [0u8; 32];
        fixed_hash.copy_from_slice(&self.hash);
        Ok(fixed_hash)
    }

    /// Get hex representation of hash
    pub fn hash_hex(&self) -> String {
        hex::encode(&self.hash)
    }

    /// Get hex representation of preimage data
    pub fn data_hex(&self) -> String {
        hex::encode(&self.data)
    }

    /// Overwrite the secret preimage bytes in place with zeros (#214).
    ///
    /// Uses volatile writes plus a sequentially consistent compiler fence so
    /// dead-store elimination cannot elide the scrub before deallocation.
    pub fn zeroize(&mut self) {
        for byte in self.data.iter_mut() {
            // SAFETY: `byte` is a valid, aligned mutable reference into `self.data`.
            unsafe {
                std::ptr::write_volatile(byte as *mut u8, 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// True when all preimage secret bytes have been overwritten with zero.
    pub fn is_zeroized(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }
}

impl Drop for Preimage {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug)]
pub struct PreimageManager {
    generated_preimages: Vec<Preimage>,
}

impl PreimageManager {
    pub fn new() -> Self {
        Self {
            generated_preimages: Vec::new(),
        }
    }

    /// Generate a new preimage and store it
    pub fn generate(&mut self, size: usize) -> Result<Preimage> {
        let preimage = Preimage::generate(size)?;
        self.generated_preimages.push(preimage.clone());
        Ok(preimage)
    }

    /// Get a stored preimage by hash
    pub fn get_by_hash(&self, hash: &[u8]) -> Option<&Preimage> {
        self.generated_preimages.iter().find(|p| p.hash == hash)
    }

    /// Get a stored preimage by hex hash
    pub fn get_by_hash_hex(&self, hash_hex: &str) -> Option<&Preimage> {
        if let Ok(hash_bytes) = hex::decode(hash_hex) {
            self.get_by_hash(&hash_bytes)
        } else {
            None
        }
    }

    /// Remove a preimage from storage and explicitly zeroize its secret bytes (#214)
    pub fn remove_by_hash(&mut self, hash: &[u8]) -> bool {
        let index = self.generated_preimages.iter().position(|p| p.hash == hash);

        if let Some(index) = index {
            let mut removed = self.generated_preimages.remove(index);
            removed.zeroize();
            true
        } else {
            false
        }
    }

    /// Zeroize and clear all stored preimages (#214)
    pub fn clear(&mut self) {
        for preimage in self.generated_preimages.iter_mut() {
            preimage.zeroize();
        }
        self.generated_preimages.clear();
    }

    /// Get count of stored preimages
    pub fn count(&self) -> usize {
        self.generated_preimages.len()
    }
}

impl Default for PreimageManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preimage_generation() {
        let preimage = Preimage::generate(32).unwrap();
        assert_eq!(preimage.data.len(), 32);
        assert_eq!(preimage.hash.len(), 32);
        assert!(preimage.created_at > 0);
    }

    #[test]
    fn test_preimage_from_seed() {
        let preimage = Preimage::from_seed("test_seed").unwrap();
        assert_eq!(preimage.data, b"test_seed");
        assert_eq!(preimage.hash.len(), 32);

        // Verify hash consistency
        let preimage2 = Preimage::from_seed("test_seed").unwrap();
        assert_eq!(preimage.hash, preimage2.hash);
    }

    #[test]
    fn test_hash_verification() {
        let preimage = Preimage::generate(16).unwrap();
        assert!(preimage.verify_hash(&preimage.hash));

        let wrong_hash = vec![0u8; 32];
        assert!(!preimage.verify_hash(&wrong_hash));
    }

    #[test]
    fn test_preimage_manager() {
        let mut manager = PreimageManager::new();
        assert_eq!(manager.count(), 0);

        let preimage = manager.generate(64).unwrap();
        assert_eq!(manager.count(), 1);

        let retrieved = manager.get_by_hash(&preimage.hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, preimage.data);

        let removed = manager.remove_by_hash(&preimage.hash);
        assert!(removed);
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_preimage_explicit_zeroize_scrubs_secret_bytes() {
        let mut preimage = Preimage::from_seed("super_secret_atomic_swap_preimage").unwrap();
        let original_hash = preimage.hash.clone();
        assert!(!preimage.is_zeroized());

        preimage.zeroize();

        assert!(preimage.is_zeroized());
        assert!(preimage.data.iter().all(|&b| b == 0));
        // Public commitment hash remains intact for audit reference.
        assert_eq!(preimage.hash, original_hash);
    }

    #[test]
    fn test_preimage_manager_clear_zeroizes_and_empties_store() {
        let mut manager = PreimageManager::new();
        let p1 = manager.generate(32).unwrap();
        let p2 = manager.generate(32).unwrap();
        assert_eq!(manager.count(), 2);

        manager.clear();
        assert_eq!(manager.count(), 0);
        assert!(manager.get_by_hash(&p1.hash).is_none());
        assert!(manager.get_by_hash(&p2.hash).is_none());
    }
}
