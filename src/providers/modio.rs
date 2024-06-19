use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::TryStreamExt;
use itertools::Itertools;
#[cfg(test)]
use mockall::{automock, predicate::*};

use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use task_local_extensions::Extensions;
use tracing::*;

use crate::providers::*;

static RE_MOD: OnceLock<regex::Regex> = OnceLock::new();
fn re_mod() -> &'static regex::Regex {
    RE_MOD.get_or_init(|| regex::Regex::new("^https://mod.io/g/drg/m/(?P<name_id>[^/#]+)(:?#(?P<mod_id>\\d+)(:?/(?P<modfile_id>\\d+))?)?$").unwrap())
}

const MODIO_DRG_ID: u32 = 2475;
const MODIO_PROVIDER_ID: &str = "modio";

inventory::submit! {
    super::ProviderFactory {
        id: MODIO_PROVIDER_ID,
        new: ModioProvider::<ModioAlt>::new_provider,
        can_provide: |url| re_mod().is_match(url),
        parameters: &[
            super::ProviderParameter {
                id: "oauth",
                name: "OAuth Token",
                description: "mod.io OAuth token",
                link: Some("https://mod.io/me/access"),
            },
        ]
    }
}

fn format_spec(name_id: &str, mod_id: u32, file_id: Option<u32>) -> ModSpecification {
    ModSpecification::new(if let Some(file_id) = file_id {
        format!("https://mod.io/g/drg/m/{}#{}/{}", name_id, mod_id, file_id)
    } else {
        format!("https://mod.io/g/drg/m/{}#{}", name_id, mod_id)
    })
}

pub struct ModioProvider<M: DrgModio> {
    modio: M,
}

impl<M: DrgModio + 'static> ModioProvider<M> {
    fn new_provider(
        parameters: &HashMap<String, String>,
    ) -> Result<Arc<dyn ModProvider>, ProviderError> {
        Ok(Arc::new(Self::new(M::with_parameters(parameters)?)))
    }
    fn new(modio: M) -> Self {
        Self { modio }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModioCache {
    mod_id_map: HashMap<String, u32>,
    modfile_blobs: HashMap<u32, BlobRef>,
    dependencies: HashMap<u32, Vec<u32>>,
    mods: HashMap<u32, ModioMod>,
    last_update_time: Option<SystemTime>,
}

impl Default for ModioCache {
    fn default() -> Self {
        Self {
            mod_id_map: Default::default(),
            modfile_blobs: Default::default(),
            dependencies: Default::default(),
            mods: Default::default(),
            last_update_time: Some(SystemTime::now()),
        }
    }
}

#[typetag::serde]
impl ModProviderCache for ModioCache {
    fn new() -> Self {
        Default::default()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModioMod {
    name_id: String,
    name: String,
    latest_modfile: Option<u32>,
    modfiles: Vec<ModioFile>,
    tags: HashSet<String>,
}

impl ModioMod {
    fn new(mod_: ModioModResponse, modfiles: Vec<ModioFile>) -> Self {
        Self {
            name_id: mod_.name_id,
            name: mod_.name,
            latest_modfile: mod_.modfile.map(|f| f.id),
            modfiles,
            tags: mod_.tags.into_iter().map(|t| t.name).collect(),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModioModResponse {
    id: u32,
    name_id: String,
    name: String,
    profile_url: String,
    modfile: Option<ModioFileResponse>,
    tags: Vec<ModioModResponseTag>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModioModResponseTag {
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModioFileResponse {
    id: u32,
    date_added: u64,
    version: Option<String>,
    changelog: Option<String>,
    filesize: u64,
    download: ModioFileResponseDownload,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModioFileResponseDownload {
    binary_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModioFile {
    id: u32,
    date_added: u64,
    version: Option<String>,
    changelog: Option<String>,
}
impl From<ModioFileResponse> for ModioFile {
    fn from(value: ModioFileResponse) -> Self {
        Self {
            id: value.id,
            date_added: value.date_added,
            version: value.version,
            changelog: value.changelog,
        }
    }
}

#[derive(Default)]
struct LoggingMiddleware {
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        loop {
            info!(
                "request started {} {}",
                self.requests
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                req.url()
            );
            let res = next.clone().run(req.try_clone().unwrap(), extensions).await;
            if let Ok(res) = &res {
                if let Some(retry) = res.headers().get("retry-after") {
                    info!("retrying after: {}...", retry.to_str().unwrap());
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        retry.to_str().unwrap().parse::<u64>().unwrap(),
                    ))
                    .await;
                    continue;
                }
            }
            return res;
        }
    }
}

#[derive(Debug, Snafu)]
pub enum DrgModioError {
    #[snafu(display("missing OAuth token"))]
    MissingOauthToken,
    #[snafu(display("reqwest middlware error: {source}"))]
    GenericReqwestMiddlewareError { source: anyhow::Error },
    #[snafu(display("reqwest error: {source}"))]
    GenericReqwestError { source: reqwest::Error },
    #[snafu(display("failed to perform basic mod.io probe: {source}"))]
    CheckFailed { source: anyhow::Error },
    #[snafu(display("failed to fetch mod files for <{url}> (mod_id = {mod_id}): {source}"))]
    FetchModFilesFailed {
        source: anyhow::Error,
        url: String,
        mod_id: u32,
    },
    #[snafu(display(
        "failed to fetch mod file {modfile_id} for <{url}> (mod_id = {mod_id}): {source}"
    ))]
    FetchModFileFailed {
        source: anyhow::Error,
        url: String,
        mod_id: u32,
        modfile_id: u32,
    },
    #[snafu(display("failed to fetch mod <{url}> (mod_id = {mod_id}): {source}"))]
    FetchModFailed {
        source: anyhow::Error,
        url: String,
        mod_id: u32,
    },
    #[snafu(display(
        "failed to fetch dependencies for mod <{url}> (mod_id = {mod_id}): {source}"
    ))]
    FetchDependenciesFailed {
        source: anyhow::Error,
        url: String,
        mod_id: u32,
    },
    #[snafu(display("encountered mod.io-related error: {msg}"))]
    GenericError { msg: &'static str },
}

impl DrgModioError {
    pub fn opt_mod_id(&self) -> Option<u32> {
        match self {
            DrgModioError::FetchModFilesFailed { mod_id, .. }
            | DrgModioError::FetchModFileFailed { mod_id, .. }
            | DrgModioError::FetchModFailed { mod_id, .. }
            | DrgModioError::FetchDependenciesFailed { mod_id, .. } => Some(*mod_id),
            _ => None,
        }
    }
}

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait DrgModio: Sync + Send {
    fn with_parameters(parameters: &HashMap<String, String>) -> Result<Self, DrgModioError>
    where
        Self: Sized;
    async fn check(&self) -> Result<(), DrgModioError>;
    async fn fetch_mod(&self, url: String, id: u32) -> Result<ModioMod, DrgModioError>;
    async fn fetch_file(
        &self,
        url: String,
        mod_id: u32,
        modfile_id: u32,
    ) -> Result<ModioFileResponse, DrgModioError>;
    async fn fetch_dependencies(&self, url: String, mod_id: u32)
        -> Result<Vec<u32>, DrgModioError>;
    async fn fetch_mods_by_name(
        &self,
        name_id: &str,
    ) -> Result<Vec<ModioModResponse>, DrgModioError>;
    async fn fetch_mods_by_ids(
        &self,
        filter_ids: Vec<u32>,
    ) -> Result<Vec<ModioModResponse>, DrgModioError>;
    async fn fetch_mod_updates_since(
        &self,
        mod_ids: Vec<u32>,
        last_update: u64,
    ) -> Result<HashSet<u32>, DrgModioError>;
    async fn download(
        &self,
        mod_id: u32,
        file_id: u32,
    ) -> futures::stream::BoxStream<'static, Result<bytes::Bytes, DrgModioError>>;
}

struct ModioAlt {
    client: reqwest_middleware::ClientWithMiddleware,
    oauth: String,
}
impl ModioAlt {
    async fn get<I: DeserializeOwned, U: AsRef<str>>(
        &self,
        endpoint: U,
    ) -> Result<I, DrgModioError> {
        self.client
            .get(&format!(
                "https://api.mod.io/v1/games/{MODIO_DRG_ID}/{}",
                endpoint.as_ref()
            ))
            .header("Authorization", format!("Bearer {}", self.oauth))
            .send()
            .await
            // TODO clean up this nonsense
            .map_err(Into::<anyhow::Error>::into)
            .context(GenericReqwestMiddlewareSnafu)?
            .error_for_status()
            .map_err(Into::<anyhow::Error>::into)
            .context(GenericReqwestMiddlewareSnafu)?
            .json::<I>()
            .await
            .context(GenericReqwestSnafu)
    }
    async fn fetch_list<I: DeserializeOwned>(
        &self,
        endpoint: &str,
        query: &str,
    ) -> Result<Vec<I>, DrgModioError> {
        #[derive(Deserialize)]
        #[allow(unused)]
        struct ResultPage<Data> {
            data: Vec<Data>,
            result_count: i64,
            result_offset: i64,
            result_limit: i64,
            result_total: i64,
        }

        let mut offset = 0;
        let mut results = vec![];

        loop {
            let url = format!("{endpoint}?_offset={offset}&{query}");
            let page: ResultPage<I> = self.get(&url).await?;
            results.extend(page.data);
            if results.len() == page.result_total as usize {
                break;
            }
            offset += page.result_count;
        }
        Ok(results)
    }
}
#[async_trait::async_trait]
impl DrgModio for ModioAlt {
    fn with_parameters(parameters: &HashMap<String, String>) -> Result<Self, DrgModioError> {
        let client: reqwest_middleware::ClientWithMiddleware =
            reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
                .with::<LoggingMiddleware>(Default::default())
                .build();
        let oauth = parameters
            .get("oauth")
            .context(MissingOauthTokenSnafu)?
            .to_string();

        Ok(Self { client, oauth })
    }

    async fn check(&self) -> Result<(), DrgModioError> {
        #[derive(Deserialize)]
        struct Empty {}
        self.get::<Empty, _>("mods?id=0")
            .await
            .map(|_| ())
            .map_err(Into::<anyhow::Error>::into)
            .context(CheckFailedSnafu)
    }

    async fn fetch_mod(&self, url: String, mod_id: u32) -> Result<ModioMod, DrgModioError> {
        let res_files = self
            .fetch_list::<ModioFileResponse>(&format!("mods/{mod_id}/files"), "id-not=0")
            .await
            .map_err(Into::<anyhow::Error>::into)
            .with_context(|_| FetchModFilesFailedSnafu {
                url: url.to_string(),
                mod_id,
            })?
            .into_iter()
            .map(Into::into)
            .collect();

        let res: ModioModResponse = self
            .get(&format!("mods/{mod_id}"))
            .await
            .map_err(Into::<anyhow::Error>::into)
            .with_context(|_| FetchModFailedSnafu { url, mod_id })?;
        Ok(ModioMod::new(res, res_files))
    }

    async fn fetch_file(
        &self,
        url: String,
        mod_id: u32,
        modfile_id: u32,
    ) -> Result<ModioFileResponse, DrgModioError> {
        let res: ModioFileResponse = self
            .get(&format!("mods/{mod_id}/files/{modfile_id}"))
            .await
            .map_err(Into::<anyhow::Error>::into)
            .with_context(|_| FetchModFileFailedSnafu {
                url,
                mod_id,
                modfile_id,
            })?;
        Ok(res)
    }

    async fn fetch_dependencies(
        &self,
        url: String,
        mod_id: u32,
    ) -> Result<Vec<u32>, DrgModioError> {
        #[derive(Deserialize)]
        struct ModDependency {
            mod_id: u32,
        }
        let res: Vec<ModDependency> = self
            .fetch_list(&format!("mods/{mod_id}/dependencies"), "")
            .await
            .map_err(Into::<anyhow::Error>::into)
            .with_context(|_| FetchDependenciesFailedSnafu { url, mod_id })?;
        Ok(res.into_iter().map(|d| d.mod_id).collect())
    }

    async fn fetch_mods_by_name(
        &self,
        name_id: &str,
    ) -> Result<Vec<ModioModResponse>, DrgModioError> {
        let params = vec![format!("name_id={name_id}"), "visible-in=0,1".to_string()];
        let res: Vec<ModioModResponse> = self
            .fetch_list("mods", &params.into_iter().join("&"))
            .await?;
        Ok(res)
    }

    async fn fetch_mods_by_ids(
        &self,
        filter_ids: Vec<u32>,
    ) -> Result<Vec<ModioModResponse>, DrgModioError> {
        let mod_list_str = filter_ids.into_iter().map(|id| id.to_string()).join(",");
        let params = vec![format!("id-in={mod_list_str}")];
        let res: Vec<ModioModResponse> = self
            .fetch_list("mods", &params.into_iter().join("&"))
            .await?;
        Ok(res)
    }

    async fn fetch_mod_updates_since(
        &self,
        mod_ids: Vec<u32>,
        last_update: u64,
    ) -> Result<HashSet<u32>, DrgModioError> {
        #[derive(Deserialize)]
        struct ResultEvent {
            mod_id: u32,
        }

        let mod_list_str = mod_ids.into_iter().map(|id| id.to_string()).join(",");
        let params = vec![
            format!("date_added-gt={last_update}"),
            format!("event_type-not-in=MOD_COMMENT_ADDED%2CMOD_COMMENT_DELETED"),
            format!("mod_id-in={mod_list_str}"),
        ];
        let res: Vec<ResultEvent> = self
            .fetch_list("mods/events", &params.into_iter().join("&"))
            .await?;
        Ok(res.iter().map(|e| e.mod_id).collect::<HashSet<_>>())
    }

    async fn download(
        &self,
        mod_id: u32,
        file_id: u32,
    ) -> futures::stream::BoxStream<'static, Result<bytes::Bytes, DrgModioError>> {
        use futures::StreamExt;
        use futures::TryFutureExt;

        let client = self.client.clone();
        let oauth = self.oauth.clone();

        ({
            let oauth = oauth.clone();
            let client = client.clone();
            || async move {
                client
                    .get(&format!(
                        "https://api.mod.io/v1/games/{MODIO_DRG_ID}/mods/{mod_id}/files/{file_id}",
                    ))
                    .header("Authorization", format!("Bearer {}", oauth))
                    .send()
                    .await
                    // TODO clean up this nonsense
                    .map_err(Into::<anyhow::Error>::into)
                    .context(GenericReqwestMiddlewareSnafu)?
                    .error_for_status()
                    .map_err(Into::<anyhow::Error>::into)
                    .context(GenericReqwestMiddlewareSnafu)?
                    .json::<ModioFileResponse>()
                    .await
                    .context(GenericReqwestSnafu)
            }
        })()
        .and_then(|res| async move {
            Ok(client
                .get(res.download.binary_url)
                .header("Authorization", format!("Bearer {}", oauth))
                .send()
                .await
                // TODO clean up this nonsense
                .map_err(Into::<anyhow::Error>::into)
                .context(GenericReqwestMiddlewareSnafu)?
                .error_for_status()
                .map_err(Into::<anyhow::Error>::into)
                .context(GenericReqwestMiddlewareSnafu)?
                .bytes_stream()
                .context(GenericReqwestSnafu))
        })
        .try_flatten_stream()
        .boxed()
    }
}

#[async_trait::async_trait]
impl<M: DrgModio + Send + Sync> ModProvider for ModioProvider<M> {
    async fn resolve_mod(
        &self,
        spec: &ModSpecification,
        update: bool,
        cache: ProviderCache,
    ) -> Result<ModResponse, ProviderError> {
        ensure!(
            !spec.url.contains("?preview="),
            PreviewLinkSnafu {
                url: spec.url.to_string()
            }
        );

        fn read_cache<F, R>(cache: &ProviderCache, update: bool, f: F) -> Option<R>
        where
            F: Fn(&ModioCache) -> Option<R>,
        {
            (!update)
                .then(|| {
                    cache
                        .read()
                        .unwrap()
                        .get::<ModioCache>(MODIO_PROVIDER_ID)
                        .and_then(f)
                })
                .flatten()
        }

        fn write_cache<F>(cache: &ProviderCache, f: F)
        where
            F: FnOnce(&mut ModioCache),
        {
            f(cache
                .write()
                .unwrap()
                .get_mut::<ModioCache>(MODIO_PROVIDER_ID))
        }

        let url = &spec.url;
        let captures = re_mod().captures(url).context(InvalidUrlSnafu {
            url: url.to_string(),
        })?;

        if let (Some(mod_id), Some(_modfile_id)) =
            (captures.name("mod_id"), captures.name("modfile_id"))
        {
            // both mod ID and modfile ID specified, but not necessarily name
            let mod_id = mod_id.as_str().parse::<u32>().unwrap();

            let mod_ =
                if let Some(mod_) = read_cache(&cache, update, |c| c.mods.get(&mod_id).cloned()) {
                    mod_
                } else {
                    let mod_ = self.modio.fetch_mod(url.clone(), mod_id).await?;

                    write_cache(&cache, |c| {
                        c.mods.insert(mod_id, mod_.clone());
                        c.mod_id_map.insert(mod_.name_id.to_owned(), mod_id);
                    });

                    mod_
                };

            let dep_ids = match read_cache(&cache, update, |c| c.dependencies.get(&mod_id).cloned())
            {
                Some(deps) => deps,
                None => {
                    let deps = self.modio.fetch_dependencies(url.clone(), mod_id).await?;
                    write_cache(&cache, |c| {
                        c.dependencies.insert(mod_id, deps.clone());
                    });
                    deps
                }
            };

            let deps = {
                // build map of (id -> name) for deps
                let mut name_map = read_cache(&cache, false, |c| {
                    Some(
                        dep_ids
                            .iter()
                            .flat_map(|id| c.mods.get(id).map(|m| (*id, m.name_id.to_string())))
                            .collect::<HashMap<_, _>>(),
                    )
                })
                .unwrap_or_default();

                let filter_ids = dep_ids
                    .iter()
                    .filter(|id| !name_map.contains_key(id))
                    .cloned()
                    .collect::<Vec<_>>();
                if !filter_ids.is_empty() {
                    let mods = self.modio.fetch_mods_by_ids(filter_ids).await?;

                    for m in &mods {
                        name_map.insert(m.id, m.name_id.to_string());
                    }

                    for m in mods {
                        let id = m.id;
                        // TODO avoid fetching mod a second time
                        let m = self.modio.fetch_mod(m.profile_url.to_string(), id).await?;
                        write_cache(&cache, |c| {
                            c.mod_id_map.insert(m.name_id.to_owned(), id);
                            c.mods.insert(id, m);
                        });
                    }
                }

                let deps = dep_ids
                    .iter()
                    .filter_map(|id| match name_map.get(id) {
                        Some(name) => Some(format_spec(name, *id, None)),
                        None => {
                            warn!("dependency ID missing from name_map: {id}");
                            None
                        }
                    })
                    .collect();

                deps
            };

            Ok(ModResponse::Resolve(ModInfo {
                provider: MODIO_PROVIDER_ID,
                spec: format_spec(&mod_.name_id, mod_id, None),
                name: mod_.name,
                versions: mod_
                    .modfiles
                    .into_iter()
                    .map(|f| format_spec(&mod_.name_id, mod_id, Some(f.id)))
                    .collect(),
                resolution: ModResolution::resolvable(url.as_str().into()),
                suggested_require: mod_.tags.contains("RequiredByAll"),
                suggested_dependencies: deps,
                modio_tags: Some(process_modio_tags(&mod_.tags)),
                modio_id: Some(mod_id),
            }))
        } else if let Some(mod_id) = captures.name("mod_id") {
            // only mod ID specified, use latest version (either cached local or remote depending)
            let mod_id = mod_id.as_str().parse::<u32>().unwrap();

            let mod_ = match read_cache(&cache, update, |c| c.mods.get(&mod_id).cloned()) {
                Some(mod_) => mod_,
                None => {
                    let mod_ = self.modio.fetch_mod(spec.url.clone(), mod_id).await?;
                    write_cache(&cache, |c| {
                        c.mods.insert(mod_id, mod_.clone());
                        c.mod_id_map.insert(mod_.name_id.to_owned(), mod_id);
                    });
                    mod_
                }
            };

            Ok(ModResponse::Redirect(format_spec(
                &mod_.name_id,
                mod_id,
                Some(
                    mod_.latest_modfile
                        .with_context(|| NoAssociatedModfileSnafu {
                            url: url.to_string(),
                        })?,
                ),
            )))
        } else {
            let name_id = captures.name("name_id").unwrap().as_str();

            let cached_id = read_cache(&cache, update, |c| c.mod_id_map.get(name_id).cloned());

            if let Some(id) = cached_id {
                let cached = read_cache(&cache, update, |c| {
                    c.mods.get(&id).and_then(|m| m.latest_modfile)
                });

                let modfile_id = match cached {
                    Some(modfile_id) => modfile_id,
                    None => {
                        let mod_ = self.modio.fetch_mod(spec.url.clone(), id).await?;
                        let modfile_id = mod_.latest_modfile;
                        write_cache(&cache, |c| {
                            c.mods.insert(id, mod_.clone());
                            c.mod_id_map.insert(mod_.name_id, id);
                        });
                        modfile_id.with_context(|| NoAssociatedModfileSnafu {
                            url: url.to_string(),
                        })?
                    }
                };

                Ok(ModResponse::Redirect(format_spec(
                    name_id,
                    id,
                    Some(modfile_id),
                )))
            } else {
                let mut mods = self.modio.fetch_mods_by_name(name_id).await?;
                if mods.len() > 1 {
                    AmbiguousModNameIdSnafu {
                        name_id: name_id.to_string(),
                    }
                    .fail()?
                } else if let Some(mod_) = mods.pop() {
                    let mod_id = mod_.id;
                    let mod_ = self.modio.fetch_mod(spec.url.clone(), mod_id).await?;
                    let modfile_id = mod_.latest_modfile;
                    write_cache(&cache, |c| {
                        c.mods.insert(mod_id, mod_.clone());
                        c.mod_id_map.insert(mod_.name_id, mod_id);
                    });
                    let file = modfile_id.with_context(|| NoAssociatedModfileSnafu {
                        url: url.to_string(),
                    })?;

                    Ok(ModResponse::Redirect(format_spec(
                        name_id,
                        mod_id,
                        Some(file),
                    )))
                } else {
                    NoModsForNameIdSnafu {
                        name_id: name_id.to_string(),
                    }
                    .fail()?
                }
            }
        }
    }

    async fn fetch_mod(
        &self,
        res: &ModResolution,
        _update: bool,
        cache: ProviderCache,
        blob_cache: &BlobCache,
        tx: Option<Sender<FetchProgress>>,
    ) -> Result<PathBuf, ProviderError> {
        let url = &res.url;
        let captures = re_mod()
            .captures(&res.url.0)
            .with_context(|| InvalidUrlSnafu {
                url: url.0.to_string(),
            })?;

        if let (Some(_name_id), Some(mod_id), Some(modfile_id)) = (
            captures.name("name_id"),
            captures.name("mod_id"),
            captures.name("modfile_id"),
        ) {
            let mod_id = mod_id.as_str().parse::<u32>().unwrap();
            let modfile_id = modfile_id.as_str().parse::<u32>().unwrap();

            Ok(
                if let Some(path) = {
                    let path = cache
                        .read()
                        .unwrap()
                        .get::<ModioCache>(MODIO_PROVIDER_ID)
                        .and_then(|c| c.modfile_blobs.get(&modfile_id))
                        .and_then(|r| blob_cache.get_path(r));
                    path
                } {
                    if let Some(tx) = tx {
                        tx.send(FetchProgress::Complete {
                            resolution: res.clone(),
                        })
                        .await
                        .unwrap();
                    }
                    path
                } else {
                    let file = self
                        .modio
                        .fetch_file(res.url.0.clone(), mod_id, modfile_id)
                        .await?;

                    let size = file.filesize;

                    info!("downloading mod {url:?}...");

                    use tokio::io::AsyncWriteExt;

                    let mut cursor = std::io::Cursor::new(vec![]);
                    let mut stream = self.modio.download(mod_id, file.id).await;
                    while let Some(bytes) = stream
                        .try_next()
                        .await
                        .with_context(|_| ModCtxtModioSnafu { mod_id })?
                    {
                        cursor
                            .write_all(&bytes)
                            .await
                            .with_context(|_| ModCtxtIoSnafu { mod_id })?;
                        if let Some(tx) = &tx {
                            tx.send(FetchProgress::Progress {
                                resolution: res.clone(),
                                progress: cursor.get_ref().len() as u64,
                                size,
                            })
                            .await
                            .unwrap();
                        }
                    }

                    let blob = blob_cache.write(&cursor.into_inner())?;
                    let path = blob_cache.get_path(&blob).unwrap();

                    cache
                        .write()
                        .unwrap()
                        .get_mut::<ModioCache>(MODIO_PROVIDER_ID)
                        .modfile_blobs
                        .insert(modfile_id, blob);

                    if let Some(tx) = tx {
                        tx.send(FetchProgress::Complete {
                            resolution: res.clone(),
                        })
                        .await
                        .unwrap();
                    }

                    path
                },
            )
        } else {
            InvalidUrlSnafu {
                url: url.0.to_string(),
            }
            .fail()?
        }
    }

    async fn update_cache(&self, cache: ProviderCache) -> Result<(), ProviderError> {
        use futures::stream::{self, StreamExt, TryStreamExt};

        let now = SystemTime::now();

        let (last_update, name_map) = {
            let cache = cache.read().unwrap();
            let Some(prov) = cache.get::<ModioCache>(MODIO_PROVIDER_ID) else {
                return Ok(()); // no existing mods, nothing to update
            };
            (
                prov.last_update_time,
                prov.mods
                    .iter()
                    .map(|(id, mod_)| (*id, mod_.name_id.clone()))
                    .collect::<HashMap<_, _>>(),
            )
        };

        let last_update = last_update
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .unwrap_or_default();

        let mod_ids = self
            .modio
            .fetch_mod_updates_since(
                name_map.keys().cloned().collect::<Vec<u32>>(),
                last_update.as_secs(),
            )
            .await?;

        // TODO most of this is ripped from generic provider code. the resolution process is overly
        // complex and should be redone now that there's a much better understanding of what
        // exactly is required
        let mut to_resolve = mod_ids
            .iter()
            .filter_map(|id| name_map.get(id).map(|name| format_spec(name, *id, None)))
            .collect::<HashSet<_>>();

        let mut mods_map = HashMap::new();

        // used to deduplicate dependencies from mods already present in the mod list
        let mut precise_mod_specs = HashSet::new();

        pub async fn resolve_mod<M: DrgModio>(
            prov: &ModioProvider<M>,
            cache: ProviderCache,
            original_spec: ModSpecification,
        ) -> Result<(ModSpecification, ModInfo), ProviderError> {
            let mut spec = original_spec.clone();
            loop {
                match prov.resolve_mod(&spec, true, cache.clone()).await? {
                    ModResponse::Resolve(m) => {
                        return Ok((original_spec, m));
                    }
                    ModResponse::Redirect(redirected_spec) => spec = redirected_spec,
                };
            }
        }

        while !to_resolve.is_empty() {
            for (u, m) in stream::iter(
                to_resolve
                    .iter()
                    .map(|u| resolve_mod(self, cache.clone(), u.to_owned())),
            )
            .boxed()
            .buffer_unordered(5)
            .try_collect::<Vec<_>>()
            .await?
            {
                precise_mod_specs.insert(m.spec.clone());
                mods_map.insert(u, m);
                to_resolve.clear();
                for m in mods_map.values() {
                    for d in &m.suggested_dependencies {
                        if !precise_mod_specs.contains(d) {
                            to_resolve.insert(d.clone());
                        }
                    }
                }
            }
        }

        let mut lock = cache.write().unwrap();
        let c = lock.get_mut::<ModioCache>(MODIO_PROVIDER_ID);
        c.last_update_time = Some(now);

        Ok(())
    }

    async fn check(&self) -> Result<(), ProviderError> {
        self.modio.check().await.map_err(Into::into)
    }

    fn get_mod_info(&self, spec: &ModSpecification, cache: ProviderCache) -> Option<ModInfo> {
        let url = &spec.url;
        let captures = re_mod().captures(url)?;

        let cache = cache.read().unwrap();
        let prov = cache.get::<ModioCache>(MODIO_PROVIDER_ID)?;

        let mod_id = if let Some(mod_id) = captures.name("mod_id") {
            mod_id.as_str().parse::<u32>().ok()
        } else if let Some(name_id) = captures.name("name_id") {
            prov.mod_id_map.get(name_id.as_str()).cloned()
        } else {
            None
        }?;
        let mod_ = prov.mods.get(&mod_id)?;
        let modfile_id = if let Some(modfile_id) = captures.name("modfile_id") {
            modfile_id.as_str().parse::<u32>().ok()
        } else {
            mod_.modfiles.last().map(|f| f.id)
        }?;

        let deps = prov
            .dependencies
            .get(&mod_id)?
            .iter()
            .map(|id| {
                prov.mods
                    .get(id)
                    .map(|m| format_spec(&m.name_id, *id, None))
            })
            .collect::<Option<Vec<_>>>()?;

        Some(ModInfo {
            provider: MODIO_PROVIDER_ID,
            spec: format_spec(&mod_.name_id, mod_id, None),
            name: mod_.name.clone(),
            versions: mod_
                .modfiles
                .iter()
                .map(|f| format_spec(&mod_.name_id, mod_id, Some(f.id)))
                .collect(),
            resolution: ModResolution::resolvable(
                format_spec(&mod_.name_id, mod_id, Some(modfile_id))
                    .url
                    .into(),
            ),
            suggested_require: mod_.tags.contains("RequiredByAll"),
            suggested_dependencies: deps,
            modio_tags: Some(process_modio_tags(&mod_.tags)),
            modio_id: Some(mod_id),
        })
    }

    fn is_pinned(&self, spec: &ModSpecification, _cache: ProviderCache) -> bool {
        let url = &spec.url;
        let captures = re_mod().captures(url).unwrap();

        captures.name("modfile_id").is_some()
    }

    fn get_version_name(&self, spec: &ModSpecification, cache: ProviderCache) -> Option<String> {
        let url = &spec.url;
        let captures = re_mod().captures(url).unwrap();

        let cache = cache.read().unwrap();
        let prov = cache.get::<ModioCache>(MODIO_PROVIDER_ID);

        let mod_id = if let Some(mod_id) = captures.name("mod_id") {
            mod_id.as_str().parse::<u32>().ok()
        } else if let Some(name_id) = captures.name("name_id") {
            prov.and_then(|c| c.mod_id_map.get(name_id.as_str()).cloned())
        } else {
            None
        };

        if let Some(mod_id) = mod_id {
            if let Some(mod_) = prov.and_then(|c| c.mods.get(&mod_id).cloned()) {
                if let Some(file_id_str) = captures.name("modfile_id") {
                    let file_id = file_id_str.as_str().parse::<u32>().unwrap();
                    if let Some(file) = mod_.modfiles.iter().find(|f| f.id == file_id) {
                        if let Some(version) = &file.version {
                            Some(format!("{} - {}", file.id, version))
                        } else {
                            Some(file_id_str.as_str().to_string())
                        }
                    } else {
                        Some(file_id_str.as_str().to_string())
                    }
                } else {
                    Some("latest".to_string())
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

fn process_modio_tags(set: &HashSet<String>) -> ModioTags {
    let qol = set.contains("QoL");
    let gameplay = set.contains("Gameplay");
    let audio = set.contains("Audio");
    let visual = set.contains("Visual");
    let framework = set.contains("Framework");
    let required_status = if set.contains("RequiredByAll") {
        RequiredStatus::RequiredByAll
    } else {
        RequiredStatus::Optional
    };
    let approval_status = if set.contains("Verified") || set.contains("Auto-Verified") {
        ApprovalStatus::Verified
    } else if set.contains("Approved") {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Sandbox
    };
    // Basic heuristic to collect all the tags which begin with a number, like `1.38`.
    let versions = set
        .iter()
        .filter(|i| i.starts_with(char::is_numeric))
        .cloned()
        .collect::<BTreeSet<String>>();

    ModioTags {
        qol,
        gameplay,
        audio,
        visual,
        framework,
        versions,
        required_status,
        approval_status,
    }
}

#[cfg(test)]
mod test {
    use super::{
        Arc, DrgModioError, HashMap, HashSet, MockDrgModio, ModProvider, ModResponse,
        ModSpecification, ModioCache, ModioFile, ModioMod, ModioModResponse, ModioProvider,
        OnceLock, RwLock, VersionAnnotatedCache, MODIO_PROVIDER_ID,
    };
    use crate::state::config::ConfigWrapper;

    #[tokio::test]
    async fn test_check_pass() {
        let mut mock = MockDrgModio::new();
        mock.expect_check().times(1).returning(|| Ok(()));
        let modio_provider = ModioProvider::new(mock);
        assert!(modio_provider.check().await.is_ok());
    }

    #[tokio::test]
    async fn test_check_fail() {
        let mut mock = MockDrgModio::new();
        mock.expect_check()
            .times(1)
            .returning(|| Err(DrgModioError::MissingOauthToken));
        let modio_provider = ModioProvider::new(mock);
        assert!(modio_provider.check().await.is_err());
    }

    struct FullMod {
        mod_: ModioMod,
        dependencies: Vec<u32>,
    }

    static MODS: OnceLock<HashMap<u32, FullMod>> = OnceLock::new();

    #[tokio::test]
    async fn test_fetch_mod_simple() {
        let mods = MODS.get_or_init(|| {
            [(
                3,
                FullMod {
                    mod_: ModioMod {
                        name_id: "test-mod".to_string(),
                        name: "Test Mod".to_string(),
                        latest_modfile: Some(5),
                        modfiles: vec![ModioFile {
                            id: 5,
                            date_added: 12345,
                            version: None,
                            changelog: None,
                        }],
                        tags: HashSet::new(),
                    },
                    dependencies: vec![],
                },
            )]
            .into_iter()
            .collect::<HashMap<_, _>>()
        });
        let mod_names = mods
            .iter()
            .map(|(id, m)| (m.mod_.name_id.as_str(), id))
            .collect::<HashMap<_, _>>();
        let mut mock = MockDrgModio::new();

        mock.expect_fetch_mods_by_name()
            .times(1)
            .returning(move |name| {
                mod_names
                    .get(name)
                    .map(|id| {
                        vec![ModioModResponse {
                            id: **id,
                            ..Default::default()
                        }]
                    })
                    .ok_or(DrgModioError::GenericError { msg: "not found" })
            });
        mock.expect_fetch_mod().times(1).returning(move |_, id| {
            mods.get(&id)
                .map(|m| m.mod_.clone())
                .ok_or(DrgModioError::GenericError { msg: "not found" })
        });
        mock.expect_fetch_dependencies()
            .times(1)
            .returning(move |_, id| {
                mods.get(&id)
                    .map(|m| m.dependencies.clone())
                    .ok_or(DrgModioError::GenericError { msg: "not found" })
            });

        let cache = Arc::new(RwLock::new(ConfigWrapper::<VersionAnnotatedCache>::memory(
            VersionAnnotatedCache::default(),
        )));

        let modio_provider = ModioProvider::new(mock);
        let resolved_mod = modio_provider
            .resolve_mod(
                &ModSpecification::new("https://mod.io/g/drg/m/test-mod".to_string()),
                false,
                cache.clone(),
            )
            .await
            .unwrap();

        let resolved_mod = match resolved_mod {
            ModResponse::Redirect(spec) => spec,
            _ => unreachable!(),
        };
        let _resolved_mod = modio_provider
            .resolve_mod(&resolved_mod, false, cache.clone())
            .await
            .unwrap();
        let lock = cache.read().unwrap();
        let modio_cache = lock.get::<ModioCache>(MODIO_PROVIDER_ID).unwrap();

        assert_eq!(
            modio_cache.mod_id_map,
            [("test-mod".to_string(), 3)].into_iter().collect()
        );
        assert_eq!(
            modio_cache.dependencies,
            [(3, vec![])].into_iter().collect()
        );
        assert_eq!(
            modio_cache.mods,
            [(3, mods.get(&3).map(|m| m.mod_.clone()).unwrap())]
                .into_iter()
                .collect()
        );
    }
}
