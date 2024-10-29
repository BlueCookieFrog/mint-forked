
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
type HKEY = u64;
type LSTATUS = i32;
type HANDLE = u64;

type CreateInterface = extern "stdcall" fn(*const u8, *mut i32) -> UNK_PTR;
type Steam_IsKnownInterface = extern "stdcall" fn(*const u8) -> bool;
type client_ReleaseThreadLocalMemory = extern "stdcall" fn(bool) -> UNK_PTR;
type BGetCallback_func = extern "stdcall" fn(HSteamPipe, *mut CallbackMsg_t) -> bool;
type FreeLastCallback_func = extern "stdcall" fn(HSteamPipe) -> bool;
type GetAPICallResult_func = extern "stdcall" fn(HSteamPipe, SteamAPICall_t, UNK_PTR, i32, i32, *mut bool) -> bool;
    
#[repr(C)] // TODO: just get rid of this entirely & replace with fillter
struct SteamIPAddress_t { p1: u64, p2:u64, p3:u32} // should be 20 bytes

#[repr(C)]
struct CallbackMsg_t{ m_hSteamUser: HSteamUser, m_iCallback: i32, m_pubParam: *mut u8, m_cubParam: i32 }

type UNK_PTR = *mut ();
const PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS: &str = "SteamUtils010\0SteamController008\0SteamInput006\0SteamUser023\0\0";
const HKCR:HKEY = 0xffffffff80000000; // HKEY_CLASSES_ROOT
const HKCU:HKEY = 0xffffffff80000001; // HKEY_CURRENT_USER
const HKLM:HKEY = 0xffffffff80000002; // HKEY_LOCAL_MACHINE
const STILL_ACTIVE:i32 = 0x00000103;


#[repr(C)]
pub struct ISteamUser__bindgen_vtable{
    GetHSteamUser:                  extern "stdcall" fn(*mut ISteamUser) -> HSteamUser,
    BLoggedOn:                      extern "stdcall" fn(*mut ISteamUser) -> bool,
    GetSteamID:                     extern "stdcall" fn(*mut ISteamUser) -> CSteamID,
    InitiateGameConnection_DEPRECATED:  extern "stdcall" fn(*mut ISteamUser, UNK_PTR, i32, CSteamID, u32, u16, bool) -> i32, // p2: void *pAuthBlob
    TerminateGameConnection_DEPRECATED: extern "stdcall" fn(*mut ISteamUser, u32, u16),
    TrackAppUsageEvent:             extern "stdcall" fn(*mut ISteamUser, CGameID, i32, *const u8), // p4 is optional??
    GetUserDataFolder:              extern "stdcall" fn(*mut ISteamUser,  *mut u8, i32) -> bool,
    StartVoiceRecording:            extern "stdcall" fn(*mut ISteamUser),
    StopVoiceRecording:             extern "stdcall" fn(*mut ISteamUser),
    GetAvailableVoice:              extern "stdcall" fn(*mut ISteamUser, *mut u32, *mut u32, u32) -> EVoiceResult, // default params 3,4
    GetVoice:                       extern "stdcall" fn(*mut ISteamUser, bool, UNK_PTR, u32, u32, bool, UNK_PTR, u32, *mut u32, u32) -> EVoiceResult,
    DecompressVoice:                extern "stdcall" fn(*mut ISteamUser, UNK_PTR, u32, UNK_PTR, u32, *mut u32, u32) -> EVoiceResult,
    GetVoiceOptimalSampleRate:      extern "stdcall" fn(*mut ISteamUser) -> u32,
    GetAuthSessionTicket:           extern "stdcall" fn(*mut ISteamUser, *mut u8, i32, *mut u32, UNK_PTR) -> HAuthTicket, // p5 : SteamNetworkingIdentity
    GetAuthTicketForWebApi:         extern "stdcall" fn(*mut ISteamUser, *mut u8) -> HAuthTicket,
    BeginAuthSession:               extern "stdcall" fn(*mut ISteamUser, *mut u8, i32, CSteamID) -> EBeginAuthSessionResult,
    EndAuthSession:                 extern "stdcall" fn(*mut ISteamUser, CSteamID),
    CancelAuthTicket:               extern "stdcall" fn(*mut ISteamUser, HAuthTicket),
    UserHasLicenseForApp:           extern "stdcall" fn(*mut ISteamUser, CSteamID, AppId_t) -> EUserHasLicenseForAppResult,
    BIsBehindNAT:                   extern "stdcall" fn(*mut ISteamUser) -> bool,
    AdvertiseGame:                  extern "stdcall" fn(*mut ISteamUser, CSteamID, u32, u16),
    RequestEncryptedAppTicket:      extern "stdcall" fn(*mut ISteamUser, *mut u8, i32) -> SteamAPICall_t,
    GetEncryptedAppTicket:          extern "stdcall" fn(*mut ISteamUser, *mut u8, i32, *mut u32) -> bool,
    GetGameBadgeLevel:              extern "stdcall" fn(*mut ISteamUser, i32, bool) -> i32,
    GetPlayerSteamLevel:            extern "stdcall" fn(*mut ISteamUser) -> i32,
    RequestStoreAuthURL:            extern "stdcall" fn(*mut ISteamUser, *mut u8) -> SteamAPICall_t,
    BIsPhoneVerified:               extern "stdcall" fn(*mut ISteamUser) -> bool,
    BIsTwoFactorEnabled:            extern "stdcall" fn(*mut ISteamUser) -> bool,
    BIsPhoneIdentifying:            extern "stdcall" fn(*mut ISteamUser) -> bool,
    BIsPhoneRequiringVerification:  extern "stdcall" fn(*mut ISteamUser) -> bool,
    GetMarketEligibility:           extern "stdcall" fn(*mut ISteamUser) -> SteamAPICall_t,
    GetDurationControl:             extern "stdcall" fn(*mut ISteamUser) -> SteamAPICall_t,
    BSetDurationControlOnlineState: extern "stdcall" fn(*mut ISteamUser, EDurationControlOnlineState) -> bool,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamUser {
    pub vtable_: *const ISteamUser__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamUtils__bindgen_vtable(::std::os::raw::c_void);
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamUtils {
    pub vtable_: *const ISteamUtils__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamClient__bindgen_vtable{
    CreateSteamPipe:                extern "stdcall" fn(*mut ISteamClient) -> HSteamPipe,
    BReleaseSteamPipe:              extern "stdcall" fn(*mut ISteamClient, HSteamPipe) -> bool,
    ConnectToGlobalUser:            extern "stdcall" fn(*mut ISteamClient, HSteamPipe) -> HSteamUser,
    CreateLocalUser:                extern "stdcall" fn(*mut ISteamClient, *mut HSteamPipe, EAccountType) -> HSteamUser,
    ReleaseUser:                    extern "stdcall" fn(*mut ISteamClient, HSteamPipe, HSteamUser),
    GetISteamUser:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> *mut ISteamUser,
    GetISteamGameServer:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameServer
    SetLocalIPBinding:              extern "stdcall" fn(*mut ISteamClient, &SteamIPAddress_t, u16), // not sure if this one is right????
    GetISteamFriends:               extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamFriends,
    GetISteamUtils:                 extern "stdcall" fn(*mut ISteamClient, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUtils,
    GetISteamMatchmaking:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMatchmaking,
    GetISteamMatchmakingServers:    extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMatchmakingServers,
    GetISteamGenericInterface:      extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: void,
    GetISteamUserStats:             extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUserStats,
    GetISteamGameServerStats:       extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameServerStats,
    GetISteamApps:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamApps,
    GetISteamNetworking:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamNetworking,
    GetISteamRemoteStorage:         extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamRemoteStorage,
    GetISteamScreenshots:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamScreenshots,
    GetISteamGameSearch:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameSearch,
    RunFrame:                       extern "stdcall" fn(*mut ISteamClient),
    GetIPCCallCount:                extern "stdcall" fn(*mut ISteamClient) -> u32,
    SetWarningMessageHook:          extern "stdcall" fn(*mut ISteamClient, SteamAPIWarningMessageHook_t),
    BShutdownIfAllPipesClosed:      extern "stdcall" fn(*mut ISteamClient) -> bool,
    GetISteamHTTP:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamHTTP,
    GetISteamController:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamController,
    GetISteamUGC:                   extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUGC,
    GetISteamMusic:                 extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMusic,
    GetISteamMusicRemote:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMusicRemote,
    GetISteamHTMLSurface:           extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamHTMLSurface,
    DEPRECATED_Set_SteamAPI_CPostAPIResultInProcess:    extern "stdcall" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    DEPRECATED_Remove_SteamAPI_CPostAPIResultInProcess: extern "stdcall" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    Set_SteamAPI_CCheckCallbackRegisteredInProcess:     extern "stdcall" fn(*mut ISteamClient, SteamAPI_CheckCallbackRegistered_t),
    GetISteamInventory:             extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamInventory,
    GetISteamVideo:                 extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamVideo,
    GetISteamParentalSettings:      extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamParentalSettings,
    GetISteamInput:                 extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamInput,
    ISteamParties:                  extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: GetISteamParties,
    GetISteamRemotePlay:            extern "stdcall" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamRemotePlay,
    DestroyAllInterfaces:           extern "stdcall" fn(*mut ISteamClient),
}
pub unsafe fn ISteamClient_CreateSteamPipe(_self: *mut ISteamClient) -> HSteamPipe{ return ((*(*_self).vtable_).CreateSteamPipe)(_self); }
pub unsafe fn ISteamClient_ConnectToGlobalUser(_self: *mut ISteamClient, pipe: HSteamPipe) -> HSteamUser{ return ((*(*_self).vtable_).ConnectToGlobalUser)(_self, pipe); }
pub unsafe fn ISteamClient_GetISteamGenericInterface(_self: *mut ISteamClient, user: HSteamUser, pipe: HSteamPipe, interface: *const u8) -> UNK_PTR{ return ((*(*_self).vtable_).GetISteamGenericInterface)(_self, user, pipe, interface); }
pub unsafe fn ISteamClient_GetISteamUser(_self: *mut ISteamClient, user: HSteamUser, pipe: HSteamPipe, interface: *const u8) -> *mut ISteamUser{ return ((*(*_self).vtable_).GetISteamUser)(_self, user, pipe, interface); }
pub unsafe fn ISteamClient_ReleaseUser(_self: *mut ISteamClient, pipe: HSteamPipe, user: HSteamUser) { ((*(*_self).vtable_).ReleaseUser)(_self, pipe, user); }
pub unsafe fn ISteamClient_BReleaseSteamPipe(_self: *mut ISteamClient, pipe: HSteamPipe) -> bool{ return ((*(*_self).vtable_).BReleaseSteamPipe)(_self, pipe); }
pub unsafe fn ISteamClient_BShutdownIfAllPipesClosed(_self: *mut ISteamClient) -> bool{ return ((*(*_self).vtable_).BShutdownIfAllPipesClosed)(_self); }



#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamClient {
    pub vtable_: *const ISteamClient__bindgen_vtable,
}

#[link(name = "kernel32")]
#[link(name = "user32")]
extern "stdcall" {
    pub fn LoadLibraryA(lpFileName: *const u8) -> HMODULE;
    pub fn LoadLibraryExA( lpLibFileName: *const u8, hFile:u64, dwFlags: u32) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *const ();
    pub fn FreeLibrary(hModule: HMODULE) -> bool;
    pub fn RegOpenKeyExA(hKey: HKEY, lpSubKey: *const u8, ulOptions:u32, samDesired:i32, phkResult:*mut HKEY) -> LSTATUS;
    pub fn RegQueryValueExA(hKey: HKEY, lpValueName: *const u8, lpReserved:u64, lpType: *mut i32, lpData: *mut u8, lpcbData:*mut u32) -> LSTATUS;
    pub fn RegCloseKey(hKey: HKEY) -> LSTATUS;
    pub fn OpenProcess(dwDesiredAccess: i32, bInheritHandle: bool, dwProcessId:u32) -> HANDLE;
    pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut i32) -> bool;
    pub fn CloseHandle(hObject: HANDLE) -> bool;
}

pub struct steam_data{
    DAT_ISteamClient_ptr: *mut ISteamClient,
    DAT_steam_IPC_pipe: HSteamPipe,
    
    DAT_ISteamUser_ptr: *mut ISteamUser,
    DAT_steamclient_hmodule: HMODULE,
    DAT_steam_alt_IPC_pipe: HSteamPipe,
    DAT_steam_user: HSteamUser,

    DAT_steam_client_ReleaseThreadLocalMemory: client_ReleaseThreadLocalMemory,
    DAT_steam_BGetCallback_func: BGetCallback_func,
    DAT_steam_FreeLastCallback_func: FreeLastCallback_func,
    DAT_steam_GetAPICallResult_func: GetAPICallResult_func,
}

// FINISHED
unsafe fn SteamAPI_IsSteamRunning() -> bool{
    let mut proc_key: HKEY = 0;
    if RegOpenKeyExA(HKCU, "Software\\Valve\\Steam\\ActiveProcess\0".as_ptr(), 0, 0x20219, &mut proc_key as *mut HKEY) != 0{
        return false;
    }

    let mut dwProcessId:u32 = 0;
    let mut cbdata:u32 = 4;
    let mut _type:i32 = 0;
    if RegQueryValueExA(proc_key, "pid\0".as_ptr(), 0, &mut _type as *mut i32, &mut dwProcessId as *mut u32 as *mut u8, &mut cbdata as *mut u32) != 0 {
        RegCloseKey(proc_key);
        return false;
    }
    RegCloseKey(proc_key);
    
    let hProcess: HANDLE = OpenProcess(0x400, false, dwProcessId);
    if hProcess == 0{
        return false;
    }

    let mut exit_code:i32 = 0;
    if GetExitCodeProcess(hProcess, &mut exit_code as *mut i32)
    && (exit_code == STILL_ACTIVE) {
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

unsafe fn steam_write_install_path() -> Vec<u8>{
    let mut proc_key: HKEY = 0;
    if RegOpenKeyExA(HKCU, "Software\\Valve\\Steam\\ActiveProcess\0".as_ptr(), 0, 0x20219, &mut proc_key as *mut HKEY) != 0{
        return vec![0u8; 0];
    }
    let mut out_proc_path = [0u8; 0x410];
    let mut cbdata:u32 = 0x410;
    let mut _type:i32 = 0;
    if RegQueryValueExA(proc_key, "SteamClientDll64\0".as_ptr(), 0, &mut _type as *mut i32, out_proc_path.as_mut_ptr(), &mut cbdata as *mut u32) != 0 {
        RegCloseKey(proc_key);
        return vec![0u8; 0];
    }
    RegCloseKey(proc_key);

    // manually terminate wstring
    out_proc_path[cbdata as usize] = 0;

    // alternative method to get filename if that failed (pretty sure this cant work with our setup)
    // if (!out_buf[0]) {
    //     WCHAR alt_proc_path[0x103];
    //     alt_proc_path[0] = L'\0';
    //     if (!GetModuleFileNameW(GetModuleHandleA("steamclient64.dll"), alt_proc_path, 0x104) < 0x104){
    //         return false;
    //     }
    //     if (!WideCharToMultiByte(0xfde9, 0, alt_proc_path, -1, out_buf, 0x410, 0, 0)){
    //         return false;
    //     }
    // }
    return out_proc_path.to_vec();
}
unsafe fn init_steam_client(steam: &mut steam_data) -> i32{
    if SteamAPI_IsSteamRunning() == false{
        return 8;
    }

    let steam_install_path = steam_write_install_path();
    if steam_install_path.len() == 0{
        return 9;
    }

    let s = String::from_utf8(steam_install_path.clone()).expect("Found invalid UTF-8");
    print!("\nBOLD: path: {} \n\n", s); // NOTE: for some reason this prints the WHOLE *non-delimited* string, however its perfectly fine when cast to just a ptr
    
    let steamclient_library = LoadLibraryExA(steam_install_path.as_ptr(), 0, 8);
    if steamclient_library == 0{
        return 11;
    }

    let create_interface_func: CreateInterface = std::mem::transmute(GetProcAddress(steamclient_library, "CreateInterface\0".as_ptr()));
    if create_interface_func as *const () == std::ptr::null_mut() {
        FreeLibrary(steamclient_library);
        return 12;
    }

    steam.DAT_steam_client_ReleaseThreadLocalMemory = std::mem::transmute(GetProcAddress(steamclient_library, "Steam_ReleaseThreadLocalMemory\0".as_ptr()));

    steam.DAT_ISteamClient_ptr = (create_interface_func)("SteamClient021\0".as_ptr(), std::ptr::null_mut()).cast::<ISteamClient>();
    steam.DAT_steamclient_hmodule = steamclient_library; // not sure why this is set without resulting_interface being true
    if steam.DAT_steamclient_hmodule == 0 {
        FreeLibrary(steamclient_library);
        return 13;
    }
    return 0;
}
unsafe fn SteamAPI_Shutdown(steam: &mut steam_data){
    if steam.DAT_steam_IPC_pipe != 0 && steam.DAT_steam_user != 0{
        ISteamClient_ReleaseUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_IPC_pipe, steam.DAT_steam_user);
        steam.DAT_steam_user = 0;}

    if steam.DAT_steam_IPC_pipe != 0{
        ISteamClient_BReleaseSteamPipe(steam.DAT_ISteamClient_ptr, steam.DAT_steam_IPC_pipe);
        steam.DAT_steam_IPC_pipe = 0;}

    if steam.DAT_steam_alt_IPC_pipe != 0 {
        ISteamClient_BReleaseSteamPipe(steam.DAT_ISteamClient_ptr, steam.DAT_steam_alt_IPC_pipe);
        steam.DAT_steam_alt_IPC_pipe = 0;}
    steam.DAT_steam_client_ReleaseThreadLocalMemory = std::mem::transmute(0u64);

    if steam.DAT_ISteamClient_ptr != std::ptr::null_mut(){
        ISteamClient_BShutdownIfAllPipesClosed(steam.DAT_ISteamClient_ptr);
        steam.DAT_ISteamClient_ptr = std::ptr::null_mut();}

    if steam.DAT_steamclient_hmodule != 0{
        FreeLibrary(steam.DAT_steamclient_hmodule);
        steam.DAT_steamclient_hmodule = 0;}
}
unsafe fn init_steam() -> i32{
    let mut steam = steam_data {
        DAT_ISteamClient_ptr: std::ptr::null_mut(),
        DAT_steam_IPC_pipe: 0,
        DAT_ISteamUser_ptr: std::ptr::null_mut(),
        DAT_steamclient_hmodule: 0,
        DAT_steam_alt_IPC_pipe: 0,
        DAT_steam_user: 0,
        DAT_steam_client_ReleaseThreadLocalMemory: std::mem::transmute(0u64),
        DAT_steam_BGetCallback_func: std::mem::transmute(0u64),
        DAT_steam_FreeLastCallback_func: std::mem::transmute(0u64),
        DAT_steam_GetAPICallResult_func: std::mem::transmute(0u64),
    };

    if steam.DAT_ISteamClient_ptr != std::ptr::null_mut() {
        return 1;
    }

    let result = init_steam_client(&mut steam);
    if result != 0 {
        return result;
    }

    steam.DAT_steam_IPC_pipe = ISteamClient_CreateSteamPipe(steam.DAT_ISteamClient_ptr);
    if steam.DAT_steam_IPC_pipe == 0 {
        SteamAPI_Shutdown(&mut steam);
        return 2;
    }

    steam.DAT_steam_user = ISteamClient_ConnectToGlobalUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_IPC_pipe);
    if steam.DAT_steam_user == 0 {
        SteamAPI_Shutdown(&mut steam);
        return 3;
    }

    //let interface_str_ptr = PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS;
    // let interface_check_func: Steam_IsKnownInterface = (Steam_IsKnownInterface)GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_IsKnownInterface");
    // if (interface_check_func) {
    //     while (*interface_str_ptr) {
    //         if (!(*interface_check_func)(interface_str_ptr)) {
    //             SteamAPI_Shutdown();
    //             return 4;}
    //         // iterate string till we reach the next null terminator
    //         while (*interface_str_ptr++);
    //     }
    // }

    if steam.DAT_steam_client_ReleaseThreadLocalMemory as *const () == std::ptr::null_mut(){
        steam.DAT_steam_alt_IPC_pipe = ISteamClient_CreateSteamPipe(steam.DAT_ISteamClient_ptr);
    }
    
    let steam_utils = ISteamClient_GetISteamGenericInterface(steam.DAT_ISteamClient_ptr, 0, steam.DAT_steam_IPC_pipe, "SteamUtils010\0".as_ptr()).cast::<ISteamUtils>();
    if steam_utils == std::ptr::null_mut() {
        SteamAPI_Shutdown(&mut steam);
        return 5;
    }

    steam.DAT_ISteamUser_ptr = ISteamClient_GetISteamUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_user, steam.DAT_steam_IPC_pipe, "SteamUser023\0".as_ptr());
    if steam.DAT_ISteamUser_ptr == std::ptr::null_mut() {
        SteamAPI_Shutdown(&mut steam);
        return 6;
    }

    const app_id:u32 = 0x00085E4E;
    if std::env::var("SteamAppId").is_err() {
        std::env::set_var("SteamAppId", app_id.to_string());}
    if std::env::var("SteamGameId").is_err() {
        std::env::set_var("SteamGameId", app_id.to_string());
        std::env::set_var("SteamOverlayGameId", app_id.to_string());}
    if std::env::var("SteamOverlayGameId").is_err() {
        std::env::set_var("SteamOverlayGameId", app_id.to_string());}
    steam.DAT_steam_BGetCallback_func = std::mem::transmute(GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_BGetCallback\0".as_ptr()));
    steam.DAT_steam_FreeLastCallback_func = std::mem::transmute(GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_FreeLastCallback\0".as_ptr()));
    steam.DAT_steam_GetAPICallResult_func = std::mem::transmute(GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_GetAPICallResult\0".as_ptr()));
    return 0;
}

pub unsafe fn steam_main() -> Result<(), &'static str>{
    match (init_steam()) {
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