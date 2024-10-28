
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

type CreateInterface = *const extern "C" fn(*const u8, *mut i32) -> UNK_PTR;
type Steam_IsKnownInterface = *const extern "C" fn(*const u8) -> bool;
type client_ReleaseThreadLocalMemory = *const extern "C" fn(bool) -> UNK_PTR;
type BGetCallback_func = *const extern "C" fn(HSteamPipe, *mut CallbackMsg_t) -> bool;
type FreeLastCallback_func = *const extern "C" fn(HSteamPipe) -> bool;
type GetAPICallResult_func = *const extern "C" fn(HSteamPipe, SteamAPICall_t, UNK_PTR, i32, i32, *mut bool) -> bool;
    
#[repr(C)] // TODO: just get rid of this entirely & replace with fillter
struct SteamIPAddress_t { p1: u64, p2:u64, p3:u32} // should be 20 bytes

#[repr(C)]
struct CallbackMsg_t{ m_hSteamUser: HSteamUser, m_iCallback: i32, m_pubParam: *mut u8, m_cubParam: i32 }

type UNK_PTR = *mut u8;
const PSZ_INTERNAL_CHECK_INTERFACE_VERSIONS: &str = "SteamUtils010\0SteamController008\0SteamInput006\0SteamUser023\0\0";
const HKCR:HKEY = 0xffffffff80000000; // HKEY_CLASSES_ROOT
const HKCU:HKEY = 0xffffffff80000001; // HKEY_CURRENT_USER
const HKLM:HKEY = 0xffffffff80000002; // HKEY_LOCAL_MACHINE
const STILL_ACTIVE:i32 = 0x00000103;


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
pub struct ISteamUtils__bindgen_vtable(::std::os::raw::c_void);
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ISteamUtils {
    pub vtable_: *const ISteamUtils__bindgen_vtable,
}

#[repr(C)]
pub struct ISteamClient__bindgen_vtable{
    CreateSteamPipe:                *const extern "C" fn(*mut ISteamClient) -> HSteamPipe,
    BReleaseSteamPipe:              *const extern "C" fn(*mut ISteamClient, HSteamPipe) -> bool,
    ConnectToGlobalUser:            *const extern "C" fn(*mut ISteamClient, HSteamPipe) -> HSteamUser,
    CreateLocalUser:                *const extern "C" fn(*mut ISteamClient, *mut HSteamPipe, EAccountType) -> HSteamUser,
    ReleaseUser:                    *const extern "C" fn(*mut ISteamClient, HSteamPipe, HSteamUser),
    GetISteamUser:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> *mut ISteamUser,
    GetISteamGameServer:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameServer
    SetLocalIPBinding:              *const extern "C" fn(*mut ISteamClient, &SteamIPAddress_t, u16), // not sure if this one is right????
    GetISteamFriends:               *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamFriends,
    GetISteamUtils:                 *const extern "C" fn(*mut ISteamClient, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUtils,
    GetISteamMatchmaking:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMatchmaking,
    GetISteamMatchmakingServers:    *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMatchmakingServers,
    GetISteamGenericInterface:      *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: void,
    GetISteamUserStats:             *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUserStats,
    GetISteamGameServerStats:       *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameServerStats,
    GetISteamApps:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamApps,
    GetISteamNetworking:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamNetworking,
    GetISteamRemoteStorage:         *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamRemoteStorage,
    GetISteamScreenshots:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamScreenshots,
    GetISteamGameSearch:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamGameSearch,
    RunFrame:                       *const extern "C" fn(*mut ISteamClient),
    GetIPCCallCount:                *const extern "C" fn(*mut ISteamClient) -> u32,
    SetWarningMessageHook:          *const extern "C" fn(*mut ISteamClient, SteamAPIWarningMessageHook_t),
    BShutdownIfAllPipesClosed:      *const extern "C" fn(*mut ISteamClient) -> bool,
    GetISteamHTTP:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamHTTP,
    GetISteamController:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamController,
    GetISteamUGC:                   *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamUGC,
    GetISteamMusic:                 *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMusic,
    GetISteamMusicRemote:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamMusicRemote,
    GetISteamHTMLSurface:           *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamHTMLSurface,
    DEPRECATED_Set_SteamAPI_CPostAPIResultInProcess:    *const extern "C" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    DEPRECATED_Remove_SteamAPI_CPostAPIResultInProcess: *const extern "C" fn(*mut ISteamClient, UNK_PTR), // p2: void (*)()
    Set_SteamAPI_CCheckCallbackRegisteredInProcess:     *const extern "C" fn(*mut ISteamClient, SteamAPI_CheckCallbackRegistered_t),
    GetISteamInventory:             *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamInventory,
    GetISteamVideo:                 *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamVideo,
    GetISteamParentalSettings:      *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamParentalSettings,
    GetISteamInput:                 *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamInput,
    ISteamParties:                  *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: GetISteamParties,
    GetISteamRemotePlay:            *const extern "C" fn(*mut ISteamClient, HSteamUser, HSteamPipe, *const u8) -> UNK_PTR, // out: ISteamRemotePlay,
    DestroyAllInterfaces:           *const extern "C" fn(*mut ISteamClient),
}
pub unsafe fn ISteamClient_CreateSteamPipe(_self: *mut ISteamClient) -> HSteamPipe{ return (*(*(*_self).vtable_).CreateSteamPipe)(_self); }
pub unsafe fn ISteamClient_ConnectToGlobalUser(_self: *mut ISteamClient, pipe: HSteamPipe) -> HSteamUser{ return (*(*(*_self).vtable_).ConnectToGlobalUser)(_self, pipe); }
pub unsafe fn ISteamClient_GetISteamGenericInterface(_self: *mut ISteamClient, user: HSteamUser, pipe: HSteamPipe, interface: *const u8) -> UNK_PTR{ return (*(*(*_self).vtable_).GetISteamGenericInterface)(_self, user, pipe, interface); }
pub unsafe fn ISteamClient_GetISteamUser(_self: *mut ISteamClient, user: HSteamUser, pipe: HSteamPipe, interface: *const u8) -> *mut ISteamUser{ return (*(*(*_self).vtable_).GetISteamUser)(_self, user, pipe, interface); }
pub unsafe fn ISteamClient_ReleaseUser(_self: *mut ISteamClient, pipe: HSteamPipe, user: HSteamUser) { (*(*(*_self).vtable_).ReleaseUser)(_self, pipe, user); }
pub unsafe fn ISteamClient_BReleaseSteamPipe(_self: *mut ISteamClient, pipe: HSteamPipe) -> bool{ return (*(*(*_self).vtable_).BReleaseSteamPipe)(_self, pipe); }
pub unsafe fn ISteamClient_BShutdownIfAllPipesClosed(_self: *mut ISteamClient) -> bool{ return (*(*(*_self).vtable_).BShutdownIfAllPipesClosed)(_self); }



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
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> UNK_PTR;
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
    if RegOpenKeyExA(HKCU, "Software\\Valve\\Steam\\ActiveProcess".as_ptr(), 0, 0x20219, &mut proc_key as *mut HKEY) != 0{
        print!("\nBOLD: 1st!!!\n\n");
        return false;
    }

    print!("\nBOLD: {} @ {:p}\n\n", proc_key, & proc_key as *const HKEY);

    let fn_ptr: unsafe extern "stdcall" fn(u64, *const u8, u32, i32, *mut u64) -> i32 = RegOpenKeyExA;
    let raw_fn_ptr = fn_ptr as *const ();

    let _fn_ptr: unsafe extern "stdcall" fn(u64, *const u8, u64, *mut i32, *mut u8, *mut u32) -> i32 = RegQueryValueExA;
    let _raw_fn_ptr = _fn_ptr as *const ();

    print!("\nBOLD: RegOpenKeyExA {:p} RegQueryValueExA {:p}\n\n", raw_fn_ptr, _raw_fn_ptr);

    let mut dwProcessId:u32 = 0;
    let mut cbdata:u32 = 4;
    let mut _type:i32 = 0;
    if RegQueryValueExA(proc_key, "pid".as_ptr(), 0, &mut _type as *mut i32, &mut dwProcessId as *mut u32 as *mut u8, &mut cbdata as *mut u32) != 0 {
        RegCloseKey(proc_key);
        print!("\nBOLD: 2nd!!!\n\n");
        return false;
    }
    RegCloseKey(proc_key);
    
    let hProcess: HANDLE = OpenProcess(0x400, false, dwProcessId);
    if hProcess == 0{
        print!("\nBOLD: 3rd!!! {}, {}\n\n", dwProcessId, proc_key);
        return false;
    }

    let mut exit_code:i32 = 0;
    if GetExitCodeProcess(hProcess, &mut exit_code as *mut i32)
    && (exit_code == STILL_ACTIVE) {
        CloseHandle(hProcess);
        print!("\nBOLD: 4th!!!\n\n");
        return true;
    }

    CloseHandle(hProcess);
    print!("\nBOLD: 5th!!!\n\n");
    return false;
}

unsafe fn steam_write_install_path() -> Vec<u8>{
    let mut proc_key: HKEY = 0;
    if RegOpenKeyExA(HKCU, "Software\\Valve\\Steam\\ActiveProcess".as_ptr(), 0, 0x20219, &mut proc_key as *mut HKEY) != 0{
        return vec![0u8; 0];
    }
    let mut out_proc_path = [0u8; 0x410];
    let mut cbdata:u32 = 0x410;
    let mut _type:i32 = 0;
    if RegQueryValueExA(proc_key, "SteamClientDll64".as_ptr(), 0, &mut _type as *mut i32, out_proc_path.as_mut_ptr(), &mut cbdata as *mut u32) != 0 {
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
    
    // count chars in string (including the null terminator)
    //let path_chars = 0;
    //while (steam_install_path[path_chars++]);

    //let steamclient_path_wstr = vec![0u8; path_chars*2];
    //if (!MultiByteToWideChar(0xfde9, 0, steam_install_path, -1, steamclient_path_wstr, path_chars)) {
    //    return 10;
    //}

    //let steamclient_library: HMODULE = LoadLibraryExW(steamclient_path_wstr, 0, 8);

    //if (steamclient_library == 0) {
        let steamclient_library = LoadLibraryExA(steam_install_path.as_ptr(), 0, 8);
    //}
    if steamclient_library == 0{
        return 11;
    }
    
    let create_interface_func: CreateInterface = *GetProcAddress(steamclient_library, "CreateInterface".as_ptr()).cast::<CreateInterface>();
    if create_interface_func == std::ptr::null_mut() {
        FreeLibrary(steamclient_library);
        return 12;
    }

    steam.DAT_steam_client_ReleaseThreadLocalMemory = *GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_ReleaseThreadLocalMemory".as_ptr()).cast::<client_ReleaseThreadLocalMemory>();

    steam.DAT_ISteamClient_ptr = (*create_interface_func)("SteamClient021".as_ptr(), std::ptr::null_mut()).cast::<ISteamClient>();
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
    steam.DAT_steam_client_ReleaseThreadLocalMemory = std::ptr::null_mut();

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
        DAT_steam_client_ReleaseThreadLocalMemory: std::ptr::null_mut(),
        DAT_steam_BGetCallback_func: std::ptr::null_mut(),
        DAT_steam_FreeLastCallback_func: std::ptr::null_mut(),
        DAT_steam_GetAPICallResult_func: std::ptr::null_mut(),
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

    if steam.DAT_steam_client_ReleaseThreadLocalMemory == std::ptr::null_mut(){
        steam.DAT_steam_alt_IPC_pipe = ISteamClient_CreateSteamPipe(steam.DAT_ISteamClient_ptr);
    }
    
    let steam_utils = ISteamClient_GetISteamGenericInterface(steam.DAT_ISteamClient_ptr, 0, steam.DAT_steam_IPC_pipe, "SteamUtils010".as_ptr()).cast::<ISteamUtils>();
    if steam_utils == std::ptr::null_mut() {
        SteamAPI_Shutdown(&mut steam);
        return 5;
    }

    steam.DAT_ISteamUser_ptr = ISteamClient_GetISteamUser(steam.DAT_ISteamClient_ptr, steam.DAT_steam_user, steam.DAT_steam_IPC_pipe, "SteamUser023".as_ptr());
    if steam.DAT_ISteamUser_ptr == std::ptr::null_mut() {
        SteamAPI_Shutdown(&mut steam);
        return 6;
    }

    // app_id:u32 = steam_utils->GetAppID();
    // if (!app_id) {
    //     SteamAPI_Shutdown();
    //     return 7;}
    const app_id:u32 = 0x00085E4E;

    if std::env::var("SteamAppId").is_err() {
        std::env::set_var("SteamAppId", app_id.to_string());}
    if std::env::var("SteamGameId").is_err() {
        std::env::set_var("SteamGameId", app_id.to_string());
        std::env::set_var("SteamOverlayGameId", app_id.to_string());}
    if std::env::var("SteamOverlayGameId").is_err() {
        std::env::set_var("SteamOverlayGameId", app_id.to_string());}
    steam.DAT_steam_BGetCallback_func = *GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_BGetCallback".as_ptr()).cast::<BGetCallback_func>();
    steam.DAT_steam_FreeLastCallback_func = *GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_FreeLastCallback".as_ptr()).cast::<FreeLastCallback_func>();
    steam.DAT_steam_GetAPICallResult_func = *GetProcAddress(steam.DAT_steamclient_hmodule, "Steam_GetAPICallResult".as_ptr()).cast::<GetAPICallResult_func>();
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