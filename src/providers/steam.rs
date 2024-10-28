
type SteamAPICall_t = u64;
type HSteamPipe = i32;
type HSteamUser = u32;
type HMODULE = u64;

type HAuthTicket = u32;

type CGameID = u64;
type CSteamID = u64;
type AppId_t = u32;
type EAccountType = i32;
type EVoiceResult = i32;
type EUserHasLicenseForAppResult = i32;
type EBeginAuthSessionResult = i32;
type EDurationControlOnlineState = i32;
type SteamAPIWarningMessageHook_t = u64;
type SteamAPI_CheckCallbackRegistered_t = u64; // uhh i dont think this one is right

#[repr(C)]
struct SteamIPAddress_t { p1: u64, p2:u64, p3:u32} // should be 20 bytes

type UNK_PTR = *mut u32;

#[repr(C)]
pub struct ISteamUser__bindgen_vtable{
    GetHSteamUser:                  *const extern "C" fn(*mut ISteamUser) -> HSteamUser,
    BLoggedOn:                      *const extern "C" fn(*mut ISteamUser) -> bool,
    GetSteamID:                     *const extern "C" fn(*mut ISteamUser) -> CSteamID,
    InitiateGameConnection_DEPRECATED:  *const extern "C" fn(*mut ISteamUser, UNK_PTR, i32, CSteamID, u32, u16, bool) -> i32, // p2: void *pAuthBlob
    TerminateGameConnection_DEPRECATED: *const extern "C" fn(*mut ISteamUser, u32, u16),
    TrackAppUsageEvent:             *const extern "C" fn(*mut ISteamUser, CGameID, i32, *const u8), // p4 is optional??
    GetUserDataFolder:              *const extern "C" fn(*mut ISteamUser,  *mut u8, i32) -> bool,
    StartVoiceRecording:            *const extern "C" fn(*mut ISteamUser),
    StopVoiceRecording:             *const extern "C" fn(*mut ISteamUser),
    GetAvailableVoice:              *const extern "C" fn(*mut ISteamUser, *mut u32, *mut u32, u32) -> EVoiceResult, // default params 3,4
    GetVoice:                       *const extern "C" fn(*mut ISteamUser, bool, UNK_PTR, u32, u32, bool, UNK_PTR, u32, *mut u32, u32) -> EVoiceResult,
    DecompressVoice:                *const extern "C" fn(*mut ISteamUser, UNK_PTR, u32, UNK_PTR, u32, *mut u32, u32) -> EVoiceResult,
    GetVoiceOptimalSampleRate:      *const extern "C" fn(*mut ISteamUser) -> u32,
    GetAuthSessionTicket:           *const extern "C" fn(*mut ISteamUser, *mut u8, i32, *mut u32, UNK_PTR) -> HAuthTicket, // p5 : SteamNetworkingIdentity
    GetAuthTicketForWebApi:         *const extern "C" fn(*mut ISteamUser, *mut u8) -> HAuthTicket,
    BeginAuthSession:               *const extern "C" fn(*mut ISteamUser, *mut u8, i32, CSteamID) -> EBeginAuthSessionResult,
    EndAuthSession:                 *const extern "C" fn(*mut ISteamUser, CSteamID),
    CancelAuthTicket:               *const extern "C" fn(*mut ISteamUser, HAuthTicket),
    UserHasLicenseForApp:           *const extern "C" fn(*mut ISteamUser, CSteamID, AppId_t) -> EUserHasLicenseForAppResult,
    BIsBehindNAT:                   *const extern "C" fn(*mut ISteamUser) -> bool,
    AdvertiseGame:                  *const extern "C" fn(*mut ISteamUser, CSteamID, u32, u16),
    RequestEncryptedAppTicket:      *const extern "C" fn(*mut ISteamUser, *mut u8, i32) -> SteamAPICall_t,
    GetEncryptedAppTicket:          *const extern "C" fn(*mut ISteamUser, *mut u8, i32, *mut u32) -> bool,
    GetGameBadgeLevel:              *const extern "C" fn(*mut ISteamUser, i32, bool) -> i32,
    GetPlayerSteamLevel:            *const extern "C" fn(*mut ISteamUser) -> i32,
    RequestStoreAuthURL:            *const extern "C" fn(*mut ISteamUser, *mut u8) -> SteamAPICall_t,
    BIsPhoneVerified:               *const extern "C" fn(*mut ISteamUser) -> bool,
    BIsTwoFactorEnabled:            *const extern "C" fn(*mut ISteamUser) -> bool,
    BIsPhoneIdentifying:            *const extern "C" fn(*mut ISteamUser) -> bool,
    BIsPhoneRequiringVerification:  *const extern "C" fn(*mut ISteamUser) -> bool,
    GetMarketEligibility:           *const extern "C" fn(*mut ISteamUser) -> SteamAPICall_t,
    GetDurationControl:             *const extern "C" fn(*mut ISteamUser) -> SteamAPICall_t,
    BSetDurationControlOnlineState: *const extern "C" fn(*mut ISteamUser, EDurationControlOnlineState) -> bool,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamUser {
    pub vtable_: *const ISteamUser__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamClient__bindgen_vtable{
    CreateSteamPipe:                *const extern "C" fn(*mut ISteamClient) -> HSteamPipe,
    BReleaseSteamPipe:              *const extern "C" fn(*mut ISteamClient, HSteamPipe) -> bool,
    ConnectToGlobalUser:            *const extern "C" fn(*mut ISteamClient, HSteamPipe) -> HSteamUser,
    CreateLocalUser:                *const extern "C" fn(*mut ISteamClient, *mut HSteamPipe, EAccountType) -> HSteamUser,
    ReleaseUser:                    *const extern "C" fn(*mut ISteamClient, HSteamPipe, HSteamUser),
    GetISteamUser:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> *mut ISteamUser,
    GetISteamGameServer:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamGameServer
    SetLocalIPBinding:              *const extern "C" fn(*mut ISteamClient, &SteamIPAddress_t, u16),
    GetISteamFriends:               *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamFriends,
    GetISteamUtils:                 *const extern "C" fn(*mut ISteamClient, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamUtils,
    GetISteamMatchmaking:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamMatchmaking,
    GetISteamMatchmakingServers:    *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamMatchmakingServers,
    GetISteamGenericInterface:      *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: void,
    GetISteamUserStats:             *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamUserStats,
    GetISteamGameServerStats:       *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamGameServerStats,
    GetISteamApps:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamApps,
    GetISteamNetworking:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamNetworking,
    GetISteamRemoteStorage:         *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamRemoteStorage,
    GetISteamScreenshots:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamScreenshots,
    GetISteamGameSearch:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamGameSearch,
    RunFrame:                       *const extern "C" fn(*mut ISteamClient),
    GetIPCCallCount:                *const extern "C" fn(*mut ISteamClient) -> u32,
    SetWarningMessageHook:          *const extern "C" fn(*mut ISteamClient, SteamAPIWarningMessageHook_t),
    BShutdownIfAllPipesClosed:      *const extern "C" fn(*mut ISteamClient) -> bool,
    GetISteamHTTP:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamHTTP,
    GetISteamController:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamController,
    GetISteamUGC:                   *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamUGC,
    GetISteamMusic:                 *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamMusic,
    GetISteamMusicRemote:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamMusicRemote,
    GetISteamHTMLSurface:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamHTMLSurface,
    DEPRECATED_Set_SteamAPI_CPostAPIResultInProcess:    *const extern "C" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    DEPRECATED_Remove_SteamAPI_CPostAPIResultInProcess: *const extern "C" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    Set_SteamAPI_CCheckCallbackRegisteredInProcess:     *const extern "C" fn(*mut ISteamClient, SteamAPI_CheckCallbackRegistered_t),
    GetISteamInventory:             *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamInventory,
    GetISteamVideo:                 *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamVideo,
    GetISteamParentalSettings:      *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamParentalSettings,
    GetISteamInput:                 *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamInput,
    ISteamParties:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: GetISteamParties,
    GetISteamRemotePlay:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *mut u8) -> UNK_PTR, // out: ISteamRemotePlay,
    DestroyAllInterfaces:           *const extern "C" fn(*mut ISteamClient),
}
pub unsafe fn ISteamClient_CreateSteamPipe (_self: *mut ISteamClient) -> HSteamPipe{ return (*(*(*_self).vtable_).CreateSteamPipe)(_self); }
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamClient {
    pub vtable_: *const ISteamClient__bindgen_vtable,
}






pub struct steam_data{
    DAT_ISteamClient_ptr: *mut ISteamClient,
    DAT_steam_IPC_pipe: HSteamPipe,
    
    DAT_ISteamUser_ptr: *mut ISteamUser,
    DAT_steamclient_hmodule: HMODULE,
    DAT_steam_alt_IPC_pipe: HSteamPipe,
    DAT_steam_user: HSteamUser
}

fn init_steam_client() -> i32{
    

    // let callback:fn(*mut ISteamClient) -> i32  = SteamAPI_ISteamClient_CreateSteamPipe;

    // callback();
    return 0;
}
fn SteamAPI_Shutdown(){}
fn init_steam(interfaces: &str) -> i32{
    let steam = steam_data {
        DAT_ISteamClient_ptr: std::ptr::null_mut(),
        DAT_ISteamUser_ptr: std::ptr::null_mut(),
        DAT_steam_IPC_pipe: 0,
        DAT_steamclient_hmodule: 0,
        DAT_steam_alt_IPC_pipe: 0,
        DAT_steam_user: 0,
    };

    if steam.DAT_ISteamClient_ptr != std::ptr::null_mut() {return 1;}

    let result = init_steam_client();
    if result != 0 {return result;}


    steam.DAT_steam_IPC_pipe = ISteamClient_CreateSteamPipe(steam.DAT_ISteamClient_ptr);
    if steam.DAT_steam_IPC_pipe == 0 {
        SteamAPI_Shutdown();
        return 2;}

    steam.DAT_steam_user = SteamAPI_ISteamClient_ConnectToGlobalUser(steam.DAT_ISteamClient_ptr, DAT_steam_IPC_pipe);
    if !DAT_steam_user {
        SteamReplace::SteamAPI_Shutdown();
        return 3;}

    // verify interface versions
    if (pszInternalCheckInterfaceVersions) {
        Steam_IsKnownInterface interface_check_func = (Steam_IsKnownInterface)GetProcAddress(DAT_steamclient_hmodule, "Steam_IsKnownInterface");
        if (interface_check_func) {
            while (*pszInternalCheckInterfaceVersions) {
                if (!(*interface_check_func)(pszInternalCheckInterfaceVersions)) {
                    SteamReplace::SteamAPI_Shutdown();
                    return 4;}
                // iterate string till we reach the next null terminator
                while (*pszInternalCheckInterfaceVersions++);
            }
        }
    }

    if (!DAT_steamclient_ReleaseThreadLocalMemory) 
        DAT_steam_alt_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    
    let steam_utils:ISteamUtils* = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (!steam_utils) {
        SteamReplace::SteamAPI_Shutdown();
        return 5;}

    DAT_ISteamUser_ptr = DAT_ISteamClient_ptr->GetISteamUser(DAT_steam_IPC_pipe, DAT_steam_user, "SteamUser023");
    if (!DAT_ISteamUser_ptr) {
        SteamReplace::SteamAPI_Shutdown();
        return 6;}

    // app_id:u32 = steam_utils->GetAppID();
    // if (!app_id) {
    //     SteamReplace::SteamAPI_Shutdown();
    //     return 7;}
    const app_id:u32 = 0x00085E4E;

    let str_buf: [u8];
    if (!GetEnvironmentVariableA("SteamAppId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf_s(str_buf, (size_t)32, "%u", app_id);
        SetEnvironmentVariableA("SteamAppId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamGameId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf_s(str_buf, (size_t)32, "%llu", app_id);
        SetEnvironmentVariableA("SteamGameId", str_buf);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamOverlayGameId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf_s(str_buf, (size_t)32, "%llu", app_id);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    DAT_steam_BGetCallback_func = (Steam_BGetCallback)GetProcAddress(DAT_steamclient_hmodule, "Steam_BGetCallback");
    DAT_steam_FreeLastCallback_func = (Steam_FreeLastCallback)GetProcAddress(DAT_steamclient_hmodule, "Steam_FreeLastCallback");
    DAT_steam_GetAPICallResult_func = (Steam_GetAPICallResult)GetProcAddress(DAT_steamclient_hmodule, "Steam_GetAPICallResult");

    // not sure what our custom function would look like for this, if it even gets used??
    //DAT_ISteamClient_ptr->Set_SteamAPI_CCheckCallbackRegisteredInProcess(Threaded::SteamAPI_CheckCallbackRegistered_t_func);
    
    return 0;
}

fn steam_main() -> Result<(), &'static str>{
    const PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS: &str = "SteamUtils010\0SteamController008\0SteamInput006\0SteamUser023\0\0";
    match (init_steam(PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS)) {
     1 => return Err("steam is already running"),
     2 => return Err("Cannot create IPC pipe to Steam client process.  Steam is probably not running."),
     3 => return Err("ConnectToGlobalUser failed."),
     4 => return Err("interface check failed"),
     5 => return Err("failed to load 'SteamUtils010' interface"),
     6 => return Err("failed to load 'SteamUser023' interface"),
     7 => return Err("No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder."),
     8 => return Err("[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam."),
     9 => return Err("Could not determine Steam client install directory."),
    10 => return Err("couldn't convert path to wide string"),
    11 => return Err("Failed to load steam client module"),
    12 => return Err("Unable to locate interface factory in steamclient64.dll"),
    13 => return Err("failed to load 'SteamClient021' interface"),
     0 => {
        // Set up a background thread to run
        // std::thread HandlerThread = std::thread([&]() {
        //     while (true) {
        //         //Modio::RunPendingHandlers();
        //         std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        //         SteamAPI_RunCallbacks();
        //     }
        // });

        // Get the Steam Encrypted App Ticket
        let k_unSecretData = vec![0x39,0x66,0x37,0x61,0x62,0x64,0x36,0x33,0x37,0x35,0x63,0x34,0x61,0x33,0x66,0x64,0x35,0x30,0x61,0x37,0x32,0x62,0x30,0x39,0x31,0x31,0x31,0x35,0x63,0x62,0x32,0x33,0x37,0x32,0x64,0x35,0x65,0x35,0x61,0x63,0x37,0x61,0x37,0x37,0x31,0x39,0x65,0x35,0x34,0x30,0x35,0x33,0x30,0x62,0x32,0x39,0x37,0x65,0x63,0x34,0x62,0x65,0x37,0x39,0x00];
        //let hSteamAPICall = SteamUser()->RequestEncryptedAppTicket(&k_unSecretData, sizeof(k_unSecretData));
        //m_SteamCallResultEncryptedAppTicket.Set(&OnEncryptedAppTicketResponse);

        //registered_callbacks[EncryptedAppTicketResponse_t::k_iCallback] = (s_deps::CCallbackBase*)&EPacket::m_SteamCallResultEncryptedAppTicket;

        //SteamAuthComplete.get_future().wait();

        return Ok(());
    }
    _ => return Err("invalid steam error")
    }
}