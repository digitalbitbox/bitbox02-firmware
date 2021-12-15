use std::process::Command;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let path_to_bindings = if let Ok(cmake_dir) = std::env::var("CMAKE_CURRENT_BINARY_DIR") {
        // if we are being invoked from CMAKE, the bindings are here:
        format!("{}/rust", cmake_dir)
    } else {
        // Else we generate the list ourselves.
        //
        // For this to work you'll need to be able to call "make rust-bindgen-includes" on your
        // developer machine. We aren't using docker here because we don't really need that many
        // tools for this to work.
        //
        // In the best of worlds we would have a "rerun-if-changed=<all necessary c headers>"

        let bitbox02_sys_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let cmake_dir = format!("{}/../../../", bitbox02_sys_dir);
        let outdir = std::env::var("OUT_DIR").unwrap();

        let cmake_builddir = format!("{}/_cmake_build_dir", outdir);
        std::fs::create_dir_all(&cmake_builddir).expect("failed to create a directory");
        let out = Command::new("cmake").arg(&cmake_dir).current_dir(&cmake_builddir).output().unwrap();
        if !out.status.success() {
            println!("{}", std::str::from_utf8(&out.stdout).unwrap());
            println!("{}", std::str::from_utf8(&out.stderr).unwrap());
            panic!()
        }
        let out = Command::new("make").arg("rust-bindgen-includes").current_dir(&cmake_builddir).output().unwrap();
        if !out.status.success() {
            println!("{}", std::str::from_utf8(&out.stdout).unwrap());
            println!("{}", std::str::from_utf8(&out.stderr).unwrap());
            panic!()
        }
        let mut includes_file = File::open(format!("{}/src/rust-bindgen.flags", cmake_builddir)).unwrap();
        let mut includes = String::new();
        includes_file.read_to_string(&mut includes).unwrap();
        let includes:Vec<&str> = includes.trim().split_ascii_whitespace().collect();
        let target = std::env::var("TARGET").unwrap();
        let mut flags = vec!["-target", &target, "-DTESTING=1"];
        flags.extend(&includes);

        // generate bindings
        let generate_bindings = format!("{}/scripts/generate-bindings.sh", cmake_dir);
        let bindings = format!("{}/bindings.rs", outdir);
        let wrapper = format!("{}/wrapper.h", bitbox02_sys_dir);
        let _ = Command::new(&generate_bindings)
            .args(&[&bindings, &wrapper])
            .args(&flags)
            .output()
            .unwrap();

        outdir
    };
    println!("cargo:rustc-env=BINDINGS={}/bindings.rs", path_to_bindings);

    // If we are testing we have to build a special library called "bitbox_merged" that contain
    // both all C code and rust code. So that rust -> c -> rust interop works.
    //
    // For this to work you'll need the most recent docker container setup. You also probably need
    // to use the same version of the rust and c compiler on your machine as in the container.
    #[cfg(feature = "testing")]
    {
        use std::path::PathBuf;

        let cmake_builddir = if let Ok(cmake_builddir) = std::env::var("CMAKE_CURRENT_BINARY_DIR") {
            String::from(cmake_builddir.strip_suffix("/src").unwrap())
        } else {
            let bitbox02_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            let cmake_dir = format!("{}/../../../", bitbox02_dir);
            let outdir = std::env::var("OUT_DIR").unwrap();
            let cmake_builddir = format!("{}/_cmake_build_dir_docker", outdir);
            let docker_exec = "../../../scripts/docker_exec.sh";
            std::fs::create_dir_all(&cmake_builddir).expect("failed to create a directory");
            // paths are relative to _inside_ docker container
            let cmake_dir_pathbuf = String::from(PathBuf::from(cmake_dir).canonicalize().unwrap().to_str().unwrap());
            let outdir_in_docker = outdir.strip_prefix(&cmake_dir_pathbuf).unwrap().strip_prefix('/').unwrap();
            let cmake_builddir_in_docker = format!("{}/_cmake_build_dir_docker", outdir_in_docker);
            println!("{}", cmake_builddir_in_docker);
            let chdir_and_run = format!("cd {} && cmake ../../../../../../../../", cmake_builddir_in_docker);
            let out = Command::new(&docker_exec).arg(&chdir_and_run).output().unwrap();
            if !out.status.success() {
                println!("{}", std::str::from_utf8(&out.stdout).unwrap());
                println!("{}", std::str::from_utf8(&out.stderr).unwrap());
                panic!()
            }
            let chdir_and_run = format!("make -C {} bitbox_merged", cmake_builddir_in_docker);
            let out = Command::new(&docker_exec).arg(&chdir_and_run).output().unwrap();
            if !out.status.success() {
                println!("{}", std::str::from_utf8(&out.stdout).unwrap());
                println!("{}", std::str::from_utf8(&out.stderr).unwrap());
                panic!()
            }
            cmake_builddir
        };
        println!("cargo:rustc-link-search={}/lib", cmake_builddir);
        // c and rust code merged :O
        println!("cargo:rustc-link-lib=bitbox_merged");

        // external libs
        println!("cargo:rustc-link-lib=wallycore");
        println!("cargo:rustc-link-lib=secp256k1");
        println!("cargo:rustc-link-lib=base32");
        println!("cargo:rustc-link-lib=ctaes");
        println!("cargo:rustc-link-lib=fatfs");
        println!("cargo:rustc-link-lib=sd-mock");

        // system libs
        println!("cargo:rustc-link-lib=cmocka");
    }

}
