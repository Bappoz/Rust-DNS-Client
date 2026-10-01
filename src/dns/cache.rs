use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_VERSION: &str = "dns-cache-v1";
const LOCK_RETRIES: usize = 140;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(50);
const STALE_LOCK_AGE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CacheKey {
    domain: String,
    rr_type: u16,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    answer: String,
    expires_at: u64,
}

struct CacheLock {
    path: PathBuf,
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Cache DNS persistente. O lock permanece ativo durante a consulta para que
/// duas execucoes simultaneas nao facam a mesma requisicao de rede.
pub struct DnsCache {
    path: PathBuf,
    entries: BTreeMap<CacheKey, CacheEntry>,
    _lock: CacheLock,
}

impl DnsCache {
    pub fn open_default() -> io::Result<Option<Self>> {
        default_cache_path().map_or(Ok(None), |path| Self::open(path).map(Some))
    }

    fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }

        let lock_path = path.with_extension("lock");
        let lock = acquire_lock(lock_path)?;
        let entries = read_entries(&path)?;

        Ok(Self {
            path,
            entries,
            _lock: lock,
        })
    }

    pub fn get(&mut self, domain: &str, rr_type: u16, now: u64) -> Option<String> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        self.entries
            .get(&CacheKey::new(domain, rr_type))
            .map(|entry| entry.answer.clone())
    }

    pub fn insert(
        &mut self,
        domain: &str,
        rr_type: u16,
        answer: String,
        ttl: u32,
        now: u64,
    ) -> io::Result<()> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        if ttl == 0 {
            return self.write();
        }

        self.entries.insert(
            CacheKey::new(domain, rr_type),
            CacheEntry {
                answer,
                expires_at: now.saturating_add(ttl as u64),
            },
        );
        self.write()
    }

    fn write(&self) -> io::Result<()> {
        let temporary = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        writeln!(file, "{CACHE_VERSION}")?;
        for (key, entry) in &self.entries {
            writeln!(
                file,
                "{}\t{}\t{}\t{}",
                entry.expires_at,
                key.rr_type,
                hex_encode(key.domain.as_bytes()),
                hex_encode(entry.answer.as_bytes())
            )?;
        }
        file.sync_all()?;
        fs::rename(temporary, &self.path)
    }
}

impl CacheKey {
    fn new(domain: &str, rr_type: u16) -> Self {
        Self {
            domain: domain.trim_end_matches('.').to_ascii_lowercase(),
            rr_type,
        }
    }
}

pub fn unix_time_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_cache_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("DNS_CLIENT_CACHE") {
        return (!path.is_empty()).then(|| PathBuf::from(path));
    }
    if let Some(path) = env::var_os("XDG_CACHE_HOME") {
        return Some(PathBuf::from(path).join("rust-dns-client/cache-v1"));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(".cache/rust-dns-client/cache-v1"))
}

fn acquire_lock(path: PathBuf) -> io::Result<CacheLock> {
    for _ in 0..LOCK_RETRIES {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                return Ok(CacheLock { path });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if lock_is_stale(&path) {
                    let _ = fs::remove_file(&path);
                    continue;
                }
                thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "tempo esgotado aguardando lock do cache DNS",
    ))
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(io::Error::other))
        .is_ok_and(|age| age > STALE_LOCK_AGE)
}

fn read_entries(path: &Path) -> io::Result<BTreeMap<CacheKey, CacheEntry>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error),
    };

    let mut lines = contents.lines();
    if lines.next() != Some(CACHE_VERSION) {
        return Ok(BTreeMap::new());
    }

    let mut entries = BTreeMap::new();
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        let [expires_at, rr_type, domain, answer] = fields.as_slice() else {
            continue;
        };
        let Some(entry) = parse_entry(expires_at, rr_type, domain, answer) else {
            continue;
        };
        entries.insert(entry.0, entry.1);
    }
    Ok(entries)
}

fn parse_entry(
    expires_at: &str,
    rr_type: &str,
    domain: &str,
    answer: &str,
) -> Option<(CacheKey, CacheEntry)> {
    let expires_at = expires_at.parse().ok()?;
    let rr_type = rr_type.parse().ok()?;
    let domain = String::from_utf8(hex_decode(domain)?).ok()?;
    let answer = String::from_utf8(hex_decode(answer)?).ok()?;
    Some((
        CacheKey::new(&domain, rr_type),
        CacheEntry { answer, expires_at },
    ))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_cache_path(test_name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "rust-dns-client-{test_name}-{}-{}",
            std::process::id(),
            unix_time_now()
        ))
    }

    #[test]
    fn persists_an_entry_until_its_ttl_expires() {
        let path = temporary_cache_path("ttl");
        {
            let mut cache = DnsCache::open(path.clone()).unwrap();
            cache
                .insert("UnB.BR.", 15, "mail.unb.br".into(), 60, 1_000)
                .unwrap();
        }
        {
            let mut cache = DnsCache::open(path.clone()).unwrap();
            assert_eq!(cache.get("unb.br", 15, 1_059), Some("mail.unb.br".into()));
            assert_eq!(cache.get("unb.br", 15, 1_060), None);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn does_not_store_zero_ttl_answers() {
        let path = temporary_cache_path("zero-ttl");
        let mut cache = DnsCache::open(path.clone()).unwrap();
        cache
            .insert("unb.br", 15, "mail.unb.br".into(), 0, 1_000)
            .unwrap();
        assert_eq!(cache.get("unb.br", 15, 1_000), None);
        drop(cache);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn ignores_invalid_cache_lines() {
        let path = temporary_cache_path("invalid");
        fs::write(
            &path,
            "dns-cache-v1\ninvalid\n1060\t15\t756e622e6272\t6d61696c\n",
        )
        .unwrap();
        let mut cache = DnsCache::open(path.clone()).unwrap();
        assert_eq!(cache.get("unb.br", 15, 1_000), Some("mail".into()));
        drop(cache);
        let _ = fs::remove_file(path);
    }
}
