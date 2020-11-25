#![feature(fn_traits)]

use std::ffi::CStr;
use std::fs::{create_dir, File, remove_dir_all};
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::thread;

use detour::static_detour;
use jni::JNIEnv as JEnv;
use jni::objects::JString;
use jni::sys::{jbyteArray, jclass, jint, JNIEnv, jobject, jstring};
use walkdir::{DirEntry, WalkDir};
use winapi::_core::mem;
use winapi::shared::minwindef::{DWORD, HINSTANCE, LPVOID};
use winapi::um::libloaderapi;
use winapi::um::libloaderapi::GetProcAddress;
use wio::wide::ToWide;
use zip::CompressionMethod;
use zip::result::ZipError;
use zip::write::FileOptions;

#[cfg(not(target_os = "windows"))]
compile_error!("only for windows");

static PREFIX: &str = "[JVMDump]";
static PATH: &str = "C:\\Dump";
static DUMP_FILE: &str = "C:\\Dump\\Dump.jar";

static_detour! {
    static define_class_1_hook: unsafe extern "C" fn(*mut JNIEnv,
    jobject,
    jstring,
    jbyteArray,
    jint,
    jint,
    jobject,
    jstring) -> jclass;
}

type FnDefineClass1 = extern "C" fn(*mut JNIEnv, jobject, jstring, jbyteArray,
                                    jint, jint, jobject, jstring) -> jclass;

fn dll_attach() {
    unsafe {
        winapi::um::consoleapi::AllocConsole();
        winapi::um::wincon::SetConsoleTitleA(cstr!("JVMDump | by Slimig"));

        println!("{} initializing...", PREFIX);

        let module_name = "java.dll";
        let java_module = libloaderapi::GetModuleHandleW(module_name.to_wide_null().as_ptr());

        if java_module.is_null() {
            println!("{} java.dll module not found! exiting..", PREFIX);
            return;
        }

        println!("{} found java.dll (0x{:X})", PREFIX, java_module as usize);

        let address = GetProcAddress(java_module, cstr!("Java_java_lang_ClassLoader_defineClass1"));

        if address.is_null() {
            println!("{} function defineClass1 not found! exiting..", PREFIX);
            return;
        }

        println!("{} found defineClass1 (0x{:X})", PREFIX, address as usize);

        let hook: FnDefineClass1 = mem::transmute(address);

        define_class_1_hook
            .initialize(hook, classloader_hook).unwrap()
            .enable().unwrap();

        println!("{} hooked defineClass1", PREFIX);
        println!("{} dumping classes to '{}'", PREFIX, PATH);
    }
}

fn classloader_hook(env: *mut JNIEnv, loader: jobject, name: jstring, data: jbyteArray,
                    offset: jint, length: jint, pd: jobject, source: jstring) -> jclass {
    unsafe {
        let java = JEnv::from_raw(env.clone()).unwrap();
        let name_ptr = java.get_string_utf_chars(JString::from(name)).unwrap();

        let class_path = to_string(name_ptr).replace(".", "\\");
        let class_name: String = [class_path.split('\\').last().unwrap(), ".class"].join("");
        let path = format!("{}\\{}", PATH, class_path.replace(class_path.split('\\').last().unwrap(), ""));
        let bytes = java.convert_byte_array(data).unwrap();

        if !Path::new(path.as_str()).exists() {
            std::fs::create_dir_all(path.as_str()).unwrap();
        }

        let mut file = std::fs::File::create(format!("{}\\{}", path, class_name)).unwrap();
        match file.write_all(bytes.as_slice()) {
            Ok(_) => {
                println!("{} dumped class {}", PREFIX, class_name);
            }
            Err(_) => {
                println!("{} failed to dump {}", PREFIX, class_name);
            }
        }

        define_class_1_hook.call(env, loader, name, data, offset, length, pd, source)
    }
}

fn dll_detach() {
    unsafe {
        winapi::um::wincon::FreeConsole();
        match copy_to_jar(PATH, DUMP_FILE, CompressionMethod::Stored) {
            Ok(_) => println!("{} dumped class files copied into '{}'", PREFIX, DUMP_FILE),
            Err(e) => println!("Error: {:?}", e),
        }
    }
}

fn copy_to_jar(
    src_dir: &str,
    dst_file: &str,
    method: zip::CompressionMethod,
) -> zip::result::ZipResult<()> {
    if !Path::new(src_dir).is_dir() {
        return Err(ZipError::FileNotFound);
    }

    let path = Path::new(dst_file);
    let file = File::create(&path).unwrap();

    let walkdir = WalkDir::new(src_dir.to_string());
    let it = walkdir.into_iter();

    zip_dir(&mut it.filter_map(|e| e.ok()), src_dir, file, method)?;

    Ok(())
}

#[allow(deprecated)]
fn zip_dir<T>(it: &mut dyn Iterator<Item=DirEntry>, prefix: &str,
              writer: T, method: zip::CompressionMethod, ) -> zip::result::ZipResult<()> where T: Write + Seek, {
    let mut zip = zip::ZipWriter::new(writer);
    let options = FileOptions::default()
        .compression_method(method);

    let mut buffer = Vec::new();
    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(prefix)).unwrap();

        if path.to_str().unwrap().contains(DUMP_FILE) {
            continue;
        }

        if path.is_file() {
            zip.start_file_from_path(name, options)?;
            let mut file = File::open(path)?;

            file.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)?;
            buffer.clear();
        } else if name.as_os_str().len() != 0 {
            zip.add_directory_from_path(name, options)?;
        }
    }
    zip.finish()?;
    Result::Ok(())
}

fn init() {
    if !Path::new(PATH).exists() {
        create_dir(PATH).unwrap();
    } else {
        remove_dir_all(PATH).unwrap();
        create_dir(PATH).unwrap()
    }

    thread::spawn(move || {
        dll_attach();
    });
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: DWORD,
    reserved: LPVOID)
    -> i32
{
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;

    match call_reason {
        DLL_PROCESS_ATTACH => init(),
        DLL_PROCESS_DETACH => {
            unsafe {
                dll_detach();

                winapi::um::libloaderapi::FreeLibraryAndExitThread(reserved as _, 1);

                unreachable!()
            }
        }
        _ => ()
    }

    return true as i32;
}

fn to_string(pointer: *const i8) -> String {
    let slice = unsafe { CStr::from_ptr(pointer).to_bytes() };
    std::str::from_utf8(slice).unwrap().to_string()
}

#[macro_export]
macro_rules! cstr {
( $ literal: literal ) => {
( concat ! ( $ literal, "\0").as_ptr() as * const i8)
};
}