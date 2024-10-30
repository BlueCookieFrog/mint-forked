use std::collections::BTreeSet;
use std::ops::DerefMut;
use std::time::SystemTime;
use std::{collections::HashMap, sync::Arc};

use snafu::prelude::*;
use tokio::{
    sync::mpsc::{self, Sender},
    task::JoinHandle,
};
use tracing::*;

use super::SelfUpdateProgress;
use super::{
    request_counter::{RequestCounter, RequestID},
    App, SpecFetchProgress, WindowProviderParameters,
};
use crate::gui::LastAction;
use crate::integrate::*;
use crate::mod_lints::{LintId, LintReport};
use crate::providers::steam;
use crate::state::{ModData_v0_1_0 as ModData, ModOrGroup};
use crate::*;
use crate::{
    providers::{FetchProgress, ModInfo, ModStore},
    state::ModConfig,
};
use mint_lib::error::GenericError;
use mint_lib::mod_info::MetaConfig;
use mint_lib::update::GitHubRelease;

#[derive(Debug)]
pub struct MessageHandle<S> {
    pub rid: RequestID,
    pub handle: JoinHandle<()>,
    pub state: S,
}

#[derive(Debug)]
pub enum Message {
    ResolveMods(ResolveMods),
    Integrate(Integrate),
    FetchModProgress(FetchModProgress),
    UpdateCache(UpdateCache),
    CheckUpdates(CheckUpdates),
    LintMods(LintMods),
    SelfUpdate(SelfUpdate),
    FetchSelfUpdateProgress(FetchSelfUpdateProgress),
    FetchSubscriptions(FetchSubscriptions),
    FetchOauth(FetchOauth),
}

impl Message {
    pub fn handle(self, app: &mut App) {
        match self {
            Self::ResolveMods(msg) => msg.receive(app),
            Self::Integrate(msg) => msg.receive(app),
            Self::FetchModProgress(msg) => msg.receive(app),
            Self::UpdateCache(msg) => msg.receive(app),
            Self::CheckUpdates(msg) => msg.receive(app),
            Self::LintMods(msg) => msg.receive(app),
            Self::SelfUpdate(msg) => msg.receive(app),
            Self::FetchSelfUpdateProgress(msg) => msg.receive(app),
            Self::FetchSubscriptions(msg) => msg.receive(app),
            Self::FetchOauth(msg) => msg.receive(app),
        }
    }
}

#[derive(Debug)]
pub struct ResolveMods {
    rid: RequestID,
    specs: Vec<ModSpecification>,
    result: Result<HashMap<ModSpecification, ModInfo>, ProviderError>,
    is_dependency: bool,
}

impl ResolveMods {
    pub fn send(
        app: &mut App,
        ctx: &egui::Context,
        specs: Vec<ModSpecification>,
        is_dependency: bool,
    ) {
        let rid = app.request_counter.next();
        let store = app.state.store.clone();
        let ctx = ctx.clone();
        let tx = app.tx.clone();
        let handle = tokio::spawn(async move {
            let result = store.resolve_mods(&specs, false).await;
            tx.send(Message::ResolveMods(Self {
                rid,
                specs,
                result,
                is_dependency,
            }))
            .await
            .unwrap();
            ctx.request_repaint();
        });
        app.last_action = None;
        app.resolve_mod_rid = Some(MessageHandle {
            rid,
            handle,
            state: (),
        });
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.resolve_mod_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(resolved_mods) => {
                    let primary_mods = self
                        .specs
                        .into_iter()
                        .collect::<HashSet<ModSpecification>>();
                    for (resolved_spec, info) in resolved_mods {
                        let is_dep = self.is_dependency || !primary_mods.contains(&resolved_spec);
                        let add = if is_dep {
                            // if mod is a dependency then check if there is a disabled
                            // mod that satisfies the dependency and enable it. if it
                            // is not a dependency then assume the user explicitly
                            // wants to add a specific mod version.
                            let active_profile = app.state.mod_data.active_profile.clone();
                            !app.state.mod_data.any_mod_mut(
                                &active_profile,
                                |mc, mod_group_enabled| {
                                    if mc.spec.satisfies_dependency(&resolved_spec) {
                                        mc.enabled = true;
                                        if let Some(mod_group_enabled) = mod_group_enabled {
                                            *mod_group_enabled = true;
                                        }
                                        true
                                    } else {
                                        false
                                    }
                                },
                            )
                        } else {
                            true
                        };

                        if add {
                            let ModData {
                                active_profile,
                                profiles,
                                ..
                            } = app.state.mod_data.deref_mut().deref_mut();

                            profiles.get_mut(active_profile).unwrap().mods.insert(
                                0,
                                ModOrGroup::Individual(ModConfig {
                                    spec: info.spec.clone(),
                                    required: info.suggested_require,
                                    enabled: true,
                                    priority: 0,
                                }),
                            );
                        }
                    }
                    app.resolve_mod.clear();
                    app.state.mod_data.save().unwrap();
                    app.last_action = Some(LastAction::success(
                        "mods successfully resolved".to_string(),
                    ));
                }
                Err(ProviderError::NoProvider { url: _, factory }) => {
                    app.window_provider_parameters =
                        Some(WindowProviderParameters::new(factory, &app.state));
                    app.last_action = Some(LastAction::failure("no provider".to_string()));
                }
                Err(e) => {
                    error!("{}", e);
                    app.problematic_mod_id = e.opt_mod_id();
                    app.last_action = Some(LastAction::failure(e.to_string()));
                }
            }
            app.resolve_mod_rid = None;
        }
    }
}

#[derive(Debug)]
pub struct Integrate {
    rid: RequestID,
    result: Result<(), IntegrationError>,
}

impl Integrate {
    pub fn send(
        rc: &mut RequestCounter,
        store: Arc<ModStore>,
        mods: Vec<ModSpecification>,
        fsd_pak: PathBuf,
        config: MetaConfig,
        tx: Sender<Message>,
        ctx: egui::Context,
    ) -> MessageHandle<HashMap<ModSpecification, SpecFetchProgress>> {
        let rid = rc.next();
        MessageHandle {
            rid,
            handle: tokio::task::spawn(async move {
                let res =
                    integrate_async(store, ctx.clone(), mods, fsd_pak, config, rid, tx.clone())
                        .await;
                tx.send(Message::Integrate(Integrate { rid, result: res }))
                    .await
                    .unwrap();
                ctx.request_repaint();
            }),
            state: Default::default(),
        }
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.integrate_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(()) => {
                    info!("integration complete");
                    app.last_action = Some(LastAction::success("integration complete".to_string()));
                }
                Err(ref e)
                    if let IntegrationError::ProviderError { ref source } = e
                        && let ProviderError::NoProvider { url: _, factory } = source =>
                {
                    app.window_provider_parameters =
                        Some(WindowProviderParameters::new(factory, &app.state));
                    app.last_action = Some(LastAction::failure("no provider".to_string()));
                }
                Err(e) => {
                    error!("{}", e);
                    app.problematic_mod_id = e.opt_mod_id();
                    app.last_action = Some(LastAction::failure(e.to_string()));
                }
            }
            app.integrate_rid = None;
        }
    }
}

#[derive(Debug)]
pub struct FetchModProgress {
    rid: RequestID,
    spec: ModSpecification,
    progress: SpecFetchProgress,
}

impl FetchModProgress {
    fn receive(self, app: &mut App) {
        if let Some(MessageHandle { rid, state, .. }) = &mut app.integrate_rid {
            if *rid == self.rid {
                state.insert(self.spec, self.progress);
            }
        }
    }
}

#[derive(Debug)]
pub struct UpdateCache {
    rid: RequestID,
    result: Result<(), ProviderError>,
}

impl UpdateCache {
    pub fn send(app: &mut App) {
        let rid = app.request_counter.next();
        let tx = app.tx.clone();
        let store = app.state.store.clone();
        let handle = tokio::spawn(async move {
            let res = store.update_cache().await;
            tx.send(Message::UpdateCache(UpdateCache { rid, result: res }))
                .await
                .unwrap();
        });
        app.last_action = None;
        app.update_rid = Some(MessageHandle {
            rid,
            handle,
            state: (),
        });
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.update_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(()) => {
                    info!("cache update complete");
                    app.last_action = Some(LastAction::success(
                        "successfully updated cache".to_string(),
                    ));
                }
                Err(ProviderError::NoProvider { url: _, factory }) => {
                    app.window_provider_parameters =
                        Some(WindowProviderParameters::new(factory, &app.state));
                    app.last_action = Some(LastAction::failure("no provider".to_string()));
                }
                Err(e) => {
                    error!("{}", e);
                    app.problematic_mod_id = e.opt_mod_id();
                    app.last_action = Some(LastAction::failure(e.to_string()));
                }
            }
            app.update_rid = None;
        }
    }
}

#[derive(Debug)]
pub struct CheckUpdates {
    rid: RequestID,
    result: Result<GitHubRelease, GenericError>,
}

impl CheckUpdates {
    pub fn send(app: &mut App, ctx: &egui::Context) {
        let rid = app.request_counter.next();
        let tx = app.tx.clone();
        let ctx = ctx.clone();

        let handle = tokio::spawn(async move {
            tx.send(Message::CheckUpdates(Self {
                rid,
                result: mint_lib::update::get_latest_release().await,
            }))
            .await
            .unwrap();
            ctx.request_repaint();
        });
        app.check_updates_rid = Some(MessageHandle {
            rid,
            handle,
            state: (),
        });
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.check_updates_rid.as_ref().map(|r| r.rid) {
            app.check_updates_rid = None;
            match self.result {
                Ok(release) => {
                    if let (Ok(version), Some(Ok(release_version))) = (
                        semver::Version::parse(env!("CARGO_PKG_VERSION")),
                        release
                            .tag_name
                            .strip_prefix('v')
                            .map(semver::Version::parse),
                    ) {
                        if release_version > version {
                            app.available_update = Some(release);
                            app.show_update_time = Some(SystemTime::now());
                        }
                    }
                }
                Err(e) => tracing::warn!("failed to fetch update {e}"),
            }
        }
    }
}

async fn integrate_async(
    store: Arc<ModStore>,
    ctx: egui::Context,
    mod_specs: Vec<ModSpecification>,
    fsd_pak: PathBuf,
    config: MetaConfig,
    rid: RequestID,
    message_tx: Sender<Message>,
) -> Result<(), IntegrationError> {
    let update = false;

    let mods = store.resolve_mods(&mod_specs, update).await?;

    let to_integrate = mod_specs
        .iter()
        .map(|u| mods[u].clone())
        .collect::<Vec<_>>();
    let res_map: HashMap<ModResolution, ModSpecification> = mods
        .iter()
        .map(|(spec, info)| (info.resolution.clone(), spec.clone()))
        .collect();
    let urls = to_integrate
        .iter()
        .map(|m| &m.resolution)
        .collect::<Vec<_>>();

    let (tx, mut rx) = mpsc::channel::<FetchProgress>(10);

    tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            if let Some(spec) = res_map.get(progress.resolution()) {
                message_tx
                    .send(Message::FetchModProgress(FetchModProgress {
                        rid,
                        spec: spec.clone(),
                        progress: progress.into(),
                    }))
                    .await
                    .unwrap();
                ctx.request_repaint();
            }
        }
    });

    let paths = store.fetch_mods_ordered(&urls, update, Some(tx)).await?;

    tokio::task::spawn_blocking(|| {
        crate::integrate::integrate(
            fsd_pak,
            config,
            to_integrate.into_iter().zip(paths).collect(),
        )
    })
    .await??;

    Ok(())
}

#[derive(Debug)]
pub struct LintMods {
    rid: RequestID,
    result: Result<LintReport, IntegrationError>,
}

impl LintMods {
    pub fn send(
        rc: &mut RequestCounter,
        store: Arc<ModStore>,
        mods: Vec<ModSpecification>,
        enabled_lints: BTreeSet<LintId>,
        game_pak_path: Option<PathBuf>,
        tx: Sender<Message>,
        ctx: egui::Context,
    ) -> MessageHandle<()> {
        let rid = rc.next();

        let handle = tokio::task::spawn(async move {
            let paths_res =
                resolve_async_ordered(store, ctx.clone(), mods.clone(), rid, tx.clone()).await;
            let mod_path_pairs_res =
                paths_res.map(|paths| mods.into_iter().zip(paths).collect::<Vec<_>>());

            let report_res = match mod_path_pairs_res {
                Ok(pairs) => tokio::task::spawn_blocking(move || {
                    crate::mod_lints::run_lints(
                        &enabled_lints,
                        pairs.into_iter().collect(),
                        game_pak_path,
                    )
                })
                .await
                .unwrap()
                .map_err(Into::into),
                Err(e) => Err(e),
            };

            tx.send(Message::LintMods(LintMods {
                rid,
                result: report_res,
            }))
            .await
            .unwrap();
            ctx.request_repaint();
        });

        MessageHandle {
            rid,
            handle,
            state: Default::default(),
        }
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.lint_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(report) => {
                    info!("lint mod report complete");
                    app.lint_report = Some(report);
                    app.last_action =
                        Some(LastAction::success("lint mod report complete".to_string()));
                }
                Err(ref e)
                    if let IntegrationError::ProviderError { ref source } = e
                        && let ProviderError::NoProvider { url: _, factory } = source =>
                {
                    app.window_provider_parameters =
                        Some(WindowProviderParameters::new(factory, &app.state));
                    app.last_action = Some(LastAction::failure("no provider".to_string()));
                }
                Err(e) => {
                    error!("{}", e);
                    app.problematic_mod_id = e.opt_mod_id();
                    app.last_action = Some(LastAction::failure(e.to_string()));
                }
            }
            app.integrate_rid = None;
        }
    }
}

async fn resolve_async_ordered(
    store: Arc<ModStore>,
    ctx: egui::Context,
    mod_specs: Vec<ModSpecification>,
    rid: RequestID,
    message_tx: Sender<Message>,
) -> Result<Vec<PathBuf>, IntegrationError> {
    let update = false;

    let mods = store.resolve_mods(&mod_specs, update).await?;

    let to_integrate = mod_specs
        .iter()
        .map(|u| mods[u].clone())
        .collect::<Vec<_>>();
    let res_map: HashMap<ModResolution, ModSpecification> = mods
        .iter()
        .map(|(spec, info)| (info.resolution.clone(), spec.clone()))
        .collect();
    let urls = to_integrate
        .iter()
        .map(|m| &m.resolution)
        .collect::<Vec<&ModResolution>>();

    let (tx, mut rx) = mpsc::channel::<FetchProgress>(10);

    tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            if let Some(spec) = res_map.get(progress.resolution()) {
                message_tx
                    .send(Message::FetchModProgress(FetchModProgress {
                        rid,
                        spec: spec.clone(),
                        progress: progress.into(),
                    }))
                    .await
                    .unwrap();
                ctx.request_repaint();
            }
        }
    });

    Ok(store.fetch_mods_ordered(&urls, update, Some(tx)).await?)
}

#[derive(Debug)]
pub struct SelfUpdate {
    rid: RequestID,
    result: Result<PathBuf, IntegrationError>,
}

impl SelfUpdate {
    pub fn send(
        rc: &mut RequestCounter,
        tx: Sender<Message>,
        ctx: egui::Context,
    ) -> MessageHandle<SelfUpdateProgress> {
        let rid = rc.next();
        MessageHandle {
            rid,
            handle: tokio::task::spawn(async move {
                let result = self_update_async(ctx.clone(), rid, tx.clone()).await;
                tx.send(Message::SelfUpdate(SelfUpdate { rid, result }))
                    .await
                    .unwrap();
                ctx.request_repaint();
            }),
            state: SelfUpdateProgress::Pending,
        }
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.self_update_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(original_exe_path) => {
                    info!("self update complete");
                    app.original_exe_path = Some(original_exe_path);
                    app.last_action = Some(LastAction::success("self update complete".to_string()));
                }
                Err(e) => {
                    error!("self update failed");
                    error!("{:#?}", e);
                    app.self_update_rid = None;
                    app.last_action = Some(LastAction::failure("self update failed".to_string()));
                }
            }
            app.integrate_rid = None;
        }
    }
}

#[derive(Debug)]
pub struct FetchSelfUpdateProgress {
    rid: RequestID,
    progress: SelfUpdateProgress,
}

impl FetchSelfUpdateProgress {
    fn receive(self, app: &mut App) {
        if let Some(MessageHandle { rid, state, .. }) = &mut app.self_update_rid {
            if *rid == self.rid {
                *state = self.progress;
            }
        }
    }
}

async fn self_update_async(
    ctx: egui::Context,
    rid: RequestID,
    message_tx: Sender<Message>,
) -> Result<PathBuf, IntegrationError> {
    use futures::stream::TryStreamExt;
    use tokio::io::AsyncWriteExt;

    let (tx, mut rx) = mpsc::channel::<SelfUpdateProgress>(1);

    tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            message_tx
                .send(Message::FetchSelfUpdateProgress(FetchSelfUpdateProgress {
                    rid,
                    progress,
                }))
                .await
                .unwrap();
            ctx.request_repaint();
        }
    });

    let client = reqwest::Client::new();

    let asset_name = if cfg!(target_os = "windows") {
        "mint-x86_64-pc-windows-msvc.zip"
    } else if cfg!(target_os = "linux") {
        "mint-x86_64-unknown-linux-gnu.zip"
    } else {
        unimplemented!("unsupported platform");
    };

    info!("downloading update");

    let response = client
        .get(format!(
            "https://github.com/bluecookiefrog/mint/releases/latest/download/{asset_name}"
        ))
        .send()
        .await
        .map_err(Into::into)
        .with_context(|_| SelfUpdateFailedSnafu)?
        .error_for_status()
        .map_err(Into::into)
        .with_context(|_| SelfUpdateFailedSnafu)?;
    let size = response.content_length();
    debug!(?response);
    debug!(?size);

    let tmp_dir = tempfile::Builder::new()
        .prefix("self_update")
        .tempdir_in(std::env::current_dir()?)?;
    let tmp_archive_path = tmp_dir.path().join(asset_name);
    let mut tmp_archive = tokio::fs::File::create(&tmp_archive_path)
        .await
        .map_err(Into::into)
        .with_context(|_| SelfUpdateFailedSnafu)?;
    let mut stream = response.bytes_stream();

    let mut total_bytes_written = 0;
    while let Some(bytes) = stream
        .try_next()
        .await
        .map_err(Into::into)
        .with_context(|_| SelfUpdateFailedSnafu)?
    {
        let bytes_written = tmp_archive.write(&bytes).await?;
        total_bytes_written += bytes_written;
        if let Some(size) = size {
            tx.send(SelfUpdateProgress::Progress {
                progress: total_bytes_written as u64,
                size,
            })
            .await
            .unwrap();
        }
    }

    debug!(?tmp_dir);
    debug!(?tmp_archive_path);
    debug!(?tmp_archive);

    let original_exe_path =
        tokio::task::spawn_blocking(move || -> Result<PathBuf, IntegrationError> {
            let bin_name = if cfg!(target_os = "windows") {
                "mint.exe"
            } else if cfg!(target_os = "linux") {
                "mint"
            } else {
                unimplemented!("unsupported platform");
            };

            info!("extracting downloaded update archive");
            self_update::Extract::from_source(&tmp_archive_path)
                .archive(self_update::ArchiveKind::Zip)
                .extract_file(tmp_dir.path(), bin_name)
                .map_err(Into::into)
                .with_context(|_| SelfUpdateFailedSnafu)?;

            info!("replacing old executable with new executable");
            let tmp_file = tmp_dir.path().join("replacement_tmp");
            let bin_path = tmp_dir.path().join(bin_name);

            let original_exe_path = std::env::current_exe()?;

            self_update::Move::from_source(&bin_path)
                .replace_using_temp(&tmp_file)
                .to_dest(&original_exe_path)
                .map_err(Into::into)
                .with_context(|_| SelfUpdateFailedSnafu)?;

            #[cfg(target_os = "linux")]
            {
                info!("setting executable permission on new executable");
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&original_exe_path, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }

            Ok(original_exe_path)
        })
        .await??;

    tx.send(SelfUpdateProgress::Complete).await.unwrap();

    info!("update successful");

    Ok(original_exe_path)
}

use modio::Error; // BAD! 
#[derive(Debug)]
pub struct FetchSubscriptions {
    rid: RequestID,
    result: Result<Vec<String>, Error>,
}

impl FetchSubscriptions {
    pub fn send(
        app: &mut App,
        ctx: &egui::Context,
        //oauth_token: &str,
    ) {
        // let rid = rc.next();
        // let ctx = ctx.clone();
        let mut _oauth_token: Option<String> = None;
        if let Some(modio_provider_params) = app.state.config.provider_parameters.get("modio")
        && let Some(oauth_token) = modio_provider_params.get("oauth")
        {
            _oauth_token = Some(oauth_token.to_string());
        } else {
            error!("ouath token fail");
            return;
        }

        let rid = app.request_counter.next();
        let ctx = ctx.clone();
        let tx = app.tx.clone();
        let handle: JoinHandle<()> = tokio::spawn(async move {
            let result = fetch_modio_subscriptions(_oauth_token.unwrap()).await;
            
            tx.send(Message::FetchSubscriptions(Self {
                rid,
                result,
            }))
            .await
            .unwrap();
            ctx.request_repaint();
        });
        app.last_action = None;
        app.fetch_subscriptions_rid = Some(MessageHandle {
            rid,
            handle,
            state: (),
        });
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.fetch_subscriptions_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(mod_list) => {
                    info!("fetch subscriptions successful");

                    let mut result: String = "".to_string();
                    for entry in mod_list.iter(){
                        result += entry;
                        result += "\n";
                    }

                    app.resolve_mod = result;
                    // we need the ctx object to call this, but just shoving it into the textbox should be good enough
                    //ResolveMods::send(app, ctx, app.parse_mods(), false); 
                    app.last_action = Some(LastAction::success("subscriptions fetching complete".to_string()));
                }
                Err(e) => {
                    error!("fetch subscriptions failed");
                    error!("{:#?}", e);
                    app.last_action = Some(LastAction::failure(e.to_string()));
                }
            }
            app.fetch_subscriptions_rid = None;
        }
    }
}


async fn fetch_modio_subscriptions(oauth_token: String) -> Result<Vec<String>, modio::Error> {
    // NOTE: temp solution because what the hell function do i call to get the modio object normally
        use crate::providers::modio::{LoggingMiddleware, MODIO_DRG_ID}; 
        use modio::{filter::prelude::*, Credentials, Modio};
        use futures::TryStreamExt;

        let credentials = Credentials::with_token("", oauth_token);
        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with::<LoggingMiddleware>(Default::default())
            .build();
        let modio = Modio::new(credentials, client.clone())?;
    //

    // create the user subscrtions query & begin iterating
    let subscriptions = modio.user().subscriptions(ModId::desc());
    let mut st = subscriptions.iter().await?;

    // process each entry into an exportable list of URLs
    let mut result: Vec<String> = Vec::new();
    while let Some(mod_) = st.try_next().await? {
        // exclude subscriptions that aren't for DRG
        if mod_.game_id == MODIO_DRG_ID{
            // profile URL is the url to the mod page
            result.push(mod_.profile_url.as_str().to_string());
        }
    }

    Ok(result)
}


#[derive(Debug)]
pub struct FetchOauth {
    rid: RequestID,
    result: Result<String, &'static str>,
    ctx: egui::Context
}

impl FetchOauth {
    pub fn send(
        app: &mut App,
        ctx: &egui::Context,
    ) {

        let rid = app.request_counter.next();
        let ctx = ctx.clone();
        let tx = app.tx.clone();
        let handle: JoinHandle<()> = tokio::spawn(async move {
            let result = fetch_steam_oauth_token().await;
            
            tx.send(Message::FetchOauth(Self {
                rid,
                result,
                ctx: ctx.clone(),
            }))
            .await
            .unwrap();
            ctx.request_repaint();
        });
        app.last_action = None;
        app.fetch_oauth_rid = Some(MessageHandle {
            rid,
            handle,
            state: (),
        });
    }

    fn receive(self, app: &mut App) {
        if Some(self.rid) == app.fetch_oauth_rid.as_ref().map(|r| r.rid) {
            match self.result {
                Ok(modio_oauth_token) => {
                    info!("fetch oauth successful");

                    for provider_factory in ModStore::get_provider_factories() {
                        info!("id: {}", provider_factory.id);
                        if provider_factory.id == "modio"{
                            app.window_provider_parameters = Some(
                                WindowProviderParameters::new(provider_factory, &app.state),
                            );
                        }
                    }
                    
                    let Some(window) = &mut app.window_provider_parameters else {
                        info!("failed doody");
                        return;
                    };
                    let mut check = false;
                    info!("progressed");

                    let mut var: Option<&mut String> = None;
                    for p in window.factory.parameters {
                        if p.id == "oauth" {
                            //info!("name: {}, desc: {}, id: {}", p.name, p.description, p.id);
                            //ui.hyperlink_to(p.name, link).on_hover_text(p.description);
                            //ui.label(p.name).on_hover_text(p.description);
                            var = Some(window.parameters.entry(p.id.to_string()).or_default());
                        }
                    }
                    if var.is_some(){
                        *(var.unwrap()) = modio_oauth_token;
                        check = true;

                        window.check_error = None;
                        let tx = window.tx.clone();
                        let ctx = self.ctx.clone();
                        let rid = app.request_counter.next();
                        let store = app.state.store.clone();
                        let params = window.parameters.clone();
                        let factory = window.factory;
                        let handle = tokio::task::spawn(async move {
                            let res = store.add_provider_checked(factory, &params).await;
                            tx.send((rid, res)).await.unwrap();
                            ctx.request_repaint();
                        });
                        window.check_rid = Some((rid, handle));
                    }




                    app.last_action = Some(LastAction::success("oauth fetching complete".to_string()));
                }
                Err(e) => {
                    error!("fetch oauth failed");
                    error!("{:#?}", e);
                    app.last_action = Some(LastAction::failure(e.to_string()));
                }
            }
            app.fetch_oauth_rid = None;
        }
    }
}



async fn fetch_steam_oauth_token() -> Result<String, &'static str> {
    let result: Result<String, &str>; // = Err("none"); // we have to declare it to access outside of unsafe block
    unsafe { 
        result = steam::steam_main();
    }



    // 
        use crate::providers::modio::LoggingMiddleware; 
        use modio::{Credentials, Modio, Result};

        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with::<LoggingMiddleware>(Default::default())
            .build();
    // 
    let api_result = Modio::new(Credentials::new("b4aab104219c1f6d752beb37e483b17b"), client); // retrieved from DRG exe?? not sure if putting this in plain text is a bad thing
    if api_result.is_err(){ return Err("Failed to instantiate Modio API account"); }
    let api = api_result.unwrap();

    use modio::auth::SteamOptions;
    let opts = SteamOptions::new(result.unwrap());
    let token_result = api.auth().external(opts).await;
    if token_result.is_err(){ return Err("Failed to auth with steam's encrypted packet"); }
    let token = token_result.unwrap();

    // debug to make sure it worked
        // let _modio_result = api.with_credentials(token);
        // let doody = _modio_result.user();
        // let super_doody = doody.current().await;
        // if super_doody.is_err(){ return Err("Failed to auth wiht oauth"); }
        // let doody = super_doody.unwrap();
        // if doody.is_none(){ return Err("Failed to get account"); }
        // let doody2 = doody.unwrap();
        // print!("found user: {}", doody2.username);
        // print!("found user: {}", doody2.profile_url);
    // 

    if token.token.is_none(){
        return Err("successfully authenticated but without an oauth token???")
    }
    let val = token.token.unwrap(); // NOTE: for some reason the generated oauth tokens last for a whole year??? you'd think it would force refresh the tokens like once every 24 hours??
    return Ok(val.value);
    //return Ok("ok epic".to_owned());
}